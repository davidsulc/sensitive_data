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
      e -> {inspect(e), inspect(__STACKTRACE__)}
    end
  end

  test "exec/1" do
    secret = "SECRET"
    test_action = fn -> Map.get(secret, :bad_key) end

    # secrets leak normally
    {error_message, stacktrace} = capture_exception_io(test_action)

    assert String.contains?(error_message, secret)

    assert String.contains?(stacktrace, secret)

    # secrets don't leak from within `exec`
    {error_message, stacktrace} =
      capture_exception_io(fn -> exec(test_action) end)

    refute String.contains?(error_message, secret)

    refute String.contains?(stacktrace, secret)

    # redaction can be customized
    custom_redaction_exception = "CUSTOM_REDACTION_EXCEPTION"
    custom_redaction_stacktrace = "CUSTOM_REDACTION_STACKTRACE"

    {error_message, stacktrace} =
      capture_exception_io(fn ->
        exec(test_action,
          exception_redaction: fn _val, _term -> custom_redaction_exception end,
          stacktrace_redaction: fn _args -> custom_redaction_stacktrace end
        )
      end)

    assert String.contains?(error_message, custom_redaction_exception)
    assert String.contains?(stacktrace, custom_redaction_stacktrace)

    refute String.contains?(error_message, secret)
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
    for into_opts <- [List, {List, [:foo, :bar]}, "foo"] do
      assert_raise(ArgumentError, "provided `:into` opts did not result in a valid wrapper", fn ->
        exec(fn -> :foo end, into: into_opts)
      end)
    end
  end

  test "gets_sensitive/2" do
    check all(input <- string(:printable, min_length: 1)) do
      me = self()

      # basic gets
      ref = make_ref()

      captured =
        capture_io(input, fn ->
          send(me, {ref, SensitiveData.gets_sensitive("Your password: ")})
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
            {ref,
             SensitiveData.gets_sensitive("Your password: ", into: {SensiDataCust, label: label})}
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
end
