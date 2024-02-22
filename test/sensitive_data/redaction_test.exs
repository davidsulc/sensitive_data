defmodule SensitiveData.RedactionTest do
  use ExUnit.Case, async: true
  doctest SensitiveData.Redaction

  import SensitiveData.Redaction

  setup do
    %{
      # the secret that must not leak
      secret: "SOME SECRET"
    }
  end

  test "redact_exception/2", %{secret: secret} do
    redactor = fn val, type ->
      case type do
        :term ->
          {h, t} = String.split_at(val, 3)
          IO.iodata_to_binary([h, List.duplicate("*", String.length(t))])

        :args ->
          List.duplicate("*** redacted args ***", length(val))
      end
    end

    # test for Exception with a :term
    exception =
      try do
        Map.get(secret, :some_key)
      rescue
        e -> e
      end

    assert %BadMapError{term: ^secret} = exception
    basic_redaction_result = %BadMapError{term: SensitiveData.Redacted}

    ## basic redaction
    assert ^basic_redaction_result = redact_exception(exception)

    ## custom redaction
    assert %BadMapError{term: "SOM********"} = redact_exception(exception, redactor)

    test_failing_custom_redaction(
      fn ->
        redact_exception(exception, fn _val, _type -> raise "oops" end)
      end,
      basic_redaction_result
    )

    # test for Exception with :args
    exception =
      try do
        Enum.map([secret], fn _, _ -> :bad end)
      rescue
        e -> e
      end

    assert %BadArityError{args: [^secret]} = exception
    ## basic redaction
    assert %BadArityError{args: [SensitiveData.Redacted]} = redact_exception(exception)

    ## custom redaction
    assert %BadArityError{args: ["*** redacted args ***"]} = redact_exception(exception, redactor)

    test_failing_custom_redaction(
      fn ->
        redact_exception(exception, fn _val, _type -> raise "oops" end)
      end,
      &match?(%BadArityError{args: [SensitiveData.Redacted]}, &1)
    )
  end

  test "redact_stacktrace/2", %{secret: secret} do
    redactor = fn args -> List.duplicate("🤫", length(args)) end

    # test stacktrace redaction for exception with :term
    stacktrace =
      try do
        Map.get(secret, :some_key)
      rescue
        _ -> __STACKTRACE__
      end

    assert {Map, :get, [^secret, :some_key, nil]} = last_stacktrace_line(stacktrace)

    basic_redaction_result = {Map, :get, 3}

    ## basic redaction
    assert ^basic_redaction_result = do_redact_stacktrace(stacktrace)

    ## custom redaction
    assert {Map, :get, ["🤫", "🤫", "🤫"]} = do_redact_stacktrace(stacktrace, redactor)

    test_failing_custom_redaction(
      fn -> do_redact_stacktrace(stacktrace, fn _args -> raise "oops" end) end,
      basic_redaction_result
    )

    # test stacktrace redaction for exception with :args
    stacktrace =
      try do
        Wrappers.SensiData.map(secret, :foo)
      rescue
        _ -> __STACKTRACE__
      end

    assert {Wrappers.SensiData, :map, [^secret, :foo, []]} = last_stacktrace_line(stacktrace)

    basic_redaction_result = {Wrappers.SensiData, :map, 3}

    ## basic redaction
    assert ^basic_redaction_result = do_redact_stacktrace(stacktrace)

    ## custom redaction
    assert {Wrappers.SensiData, :map, ["🤫", "🤫", "🤫"]} =
             do_redact_stacktrace(stacktrace, redactor)

    test_failing_custom_redaction(
      fn -> do_redact_stacktrace(stacktrace, fn _args -> raise "oops" end) end,
      basic_redaction_result
    )

    # test stacktrace redaction when there's nothing to redact (:args is just an int
    # indicating argument count)
    stacktrace =
      try do
        Enum.map([secret], fn _, _ -> :bad end)
      rescue
        _ -> __STACKTRACE__
      end

    orig_last_line = last_stacktrace_line(stacktrace)

    # this appears to have changed between Elixir v. 1.14.5 and 1.15.1
    assert match?({Enum, :"-map/2-lists^map/1-1-", 2}, orig_last_line) or
             match?({Enum, :"-map/2-lists^map/1-0-", 2}, orig_last_line)

    assert ^orig_last_line = do_redact_stacktrace(stacktrace)
    assert ^orig_last_line = do_redact_stacktrace(stacktrace, redactor)
  end

  defp test_failing_custom_redaction(callback, expected_redacted_result) do
    # with_log was only introduced in 1.13.0
    if function_exported?(ExUnit.CaptureLog, :with_log, 1) do
      {redacted_result, log} = ExUnit.CaptureLog.with_log(callback)

      case is_function(expected_redacted_result, 1) do
        false -> assert ^expected_redacted_result = redacted_result
        true -> assert expected_redacted_result.(redacted_result)
      end

      assert String.contains?(
               log,
               "Custom redaction strategy failed, falling back to `:strip` strategy"
             )
    end
  end

  # we only care about the last call (and drop the file info from the tuple)
  defp last_stacktrace_line(stacktrace), do: stacktrace |> hd() |> Tuple.delete_at(3)

  defp do_redact_stacktrace(stacktrace, strat \\ :strip) do
    stacktrace
    |> redact_stacktrace(strat)
    |> last_stacktrace_line()
  end
end
