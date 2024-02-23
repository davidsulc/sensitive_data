defmodule SensitiveDataTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import ExUnit.CaptureIO, only: [capture_io: 2]
  import ExUnitProperties

  import StreamData
  import SensitiveData
  import SensitiveData.Guards

  alias Wrappers.{SensiData, SensiDataCust}

  doctest SensitiveData

  defp capture_exception_io(fun) do
    try do
      fun.()
    rescue
      e -> {e, inspect(__STACKTRACE__)}
    end
  end

  test "exec/1" do
    secret = "SECRET"
    test_action = fn -> Map.get(secret, :bad_key) end

    # secrets leak normally
    {exception, stacktrace} = capture_exception_io(test_action)

    assert String.contains?(inspect(exception), secret)
    assert String.contains?(Exception.message(exception), secret)

    assert String.contains?(stacktrace, secret)

    # secrets don't leak from within `exec`
    {exception, stacktrace} =
      capture_exception_io(fn -> exec(test_action) end)

    refute String.contains?(inspect(exception), secret)
    refute String.contains?(Exception.message(exception), secret)

    refute String.contains?(stacktrace, secret)

    # redaction can be customized
    custom_redaction_exception = "CUSTOM_REDACTION_EXCEPTION"
    custom_redaction_stacktrace = "CUSTOM_REDACTION_STACKTRACE"

    {exception, stacktrace} =
      capture_exception_io(fn ->
        exec(test_action,
          exception_redactor: fn
            %{term: _} = e -> %{e | term: custom_redaction_exception}
            e -> e
          end,
          stacktrace_redactor: fn stacktrace ->
            with [{mod, fun, args, info} | rest] when is_list(args) <- stacktrace do
              [{mod, fun, [custom_redaction_stacktrace], info} | rest]
            end
          end
        )
      end)

    assert String.contains?(inspect(exception), custom_redaction_exception)
    assert String.contains?(Exception.message(exception), custom_redaction_exception)
    assert String.contains?(stacktrace, custom_redaction_stacktrace)

    refute String.contains?(inspect(exception), secret)
    refute String.contains?(Exception.message(exception), secret)
    refute String.contains?(stacktrace, secret)
  end

  test "exec into" do
    check all(term <- term(), label <- term()) do
      wrapped = exec(fn -> term end, into: SensiData)

      assert SensiData.unwrap(wrapped) == term
      assert is_nil(wrapped.label)
      assert is_nil(wrapped.redacted)

      wrapped_by_module = SensiData.from(fn -> term end)

      assert wrapped == wrapped_by_module

      wrapped_with_opts =
        exec(fn -> term end, into: {SensiDataCust, label: label})

      assert SensiDataCust.unwrap(wrapped_with_opts) == term
      assert wrapped_with_opts.label == label

      wrapped_with_opts_by_module =
        SensiDataCust.from(fn -> term end, label: label)

      assert wrapped_with_opts == wrapped_with_opts_by_module

      # opts get dropped if not allowed in call to `use`
      capture_log(fn ->
        wrapped_with_opts =
          exec(fn -> term end, into: {SensiData, label: label})

        assert SensiData.unwrap(wrapped_with_opts) == term
        assert is_nil(wrapped_with_opts.label)
      end)
    end
  end

  test "exec into with invalid :into target" do
    assert_invalid_into_opts_raise(fn into_opts ->
      exec(fn -> :foo end, into: into_opts)
    end)
  end

  test "exec with exception_redaction" do
    secret = "SOME SECRET"
    me = self()
    ref = make_ref()

    exception_redactor = fn e ->
      send(me, {ref, e})
      e
    end

    try do
      exec(fn -> Map.get(secret, :some_key) end, exception_redactor: exception_redactor)
    rescue
      _ -> :ok
    end

    assert_received({^ref, %BadMapError{term: ^secret}})

    try do
      exec(fn -> Enum.map([secret], fn _, _ -> :bad end) end,
        exception_redactor: exception_redactor
      )
    rescue
      _ -> :ok
    end

    assert_received({^ref, %BadArityError{args: [^secret]}})
  end

  test "exec with stacktrace_redaction" do
    secret = "SOME SECRET"
    me = self()
    ref = make_ref()

    stacktrace_redactor = fn stacktrace ->
      send(me, {ref, stacktrace})
      stacktrace
    end

    try do
      exec(fn -> Map.get(secret, :some_key) end, stacktrace_redactor: stacktrace_redactor)
    rescue
      _ -> :ok
    end

    assert_received({^ref, [{Map, :get, [^secret, :some_key, nil], _} | _]})
  end

  test "gets_sensitive/2" do
    check all(
            # remove carriage returns: they'll never be part of the
            # returned string since they in fact trigger the returning
            # of the result (i.e. pressing "enter" indicates you're
            # done with inputing the string)
            input <-
              filter(
                bind(
                  string(:printable, min_length: 1),
                  &constant(String.replace(&1, ["\n", "\r\n"], ""))
                ),
                &(String.length(&1) > 0)
              )
          ) do
      me = self()

      # basic gets
      ref = make_ref()

      captured =
        capture_io(input, fn ->
          send(me, {ref, gets_sensitive("Your password: ")})
        end)

      assert String.trim(captured) == "Your password:"
      assert_received({^ref, ^input})

      # wrapping the return value
      ref = make_ref()
      label = :my_label

      captured =
        capture_io(input, fn ->
          send(
            me,
            {ref, gets_sensitive("Your password: ", into: {SensiDataCust, label: label})}
          )
        end)

      assert String.trim(captured) == "Your password:"

      receive do
        {^ref, wrapped} ->
          assert is_sensitive(wrapped, SensiDataCust)
          assert wrapped.label == label
          assert SensiDataCust.unwrap(wrapped) == input
      after
        0 -> raise "no wrapper instance received from gets_sensitive"
      end
    end
  end

  test "gets_sensitive with invalid :into target" do
    assert_invalid_into_opts_raise(fn into_opts ->
      capture_io("foo", fn ->
        gets_sensitive("Your password: ", into: into_opts)
      end)
    end)
  end

  defp assert_invalid_into_opts_raise(callback) do
    message = SensitiveData.InvalidIntoOptionError.exception([]) |> Exception.message()

    for into_opts <- [List, {List, [:foo, :bar]}, "foo"] do
      assert_raise(ArgumentError, message, fn ->
        callback.(into_opts)
      end)
    end
  end
end
