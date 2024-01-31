defmodule SensitiveData.RedactionTest do
  use ExUnit.Case, async: true
  doctest SensitiveData.Redaction

  import SensitiveData.Redaction

  import ExUnit.CaptureLog

  setup do
    secret = "SOME SECRET"

    {exception, stacktrace} =
      try do
        Map.get(secret, :some_key)
      rescue
        e -> {e, __STACKTRACE__}
      end

    %{
      secret: secret,
      exception: exception,
      stacktrace: stacktrace
    }
  end

  test "redact_exception/2", %{secret: secret, exception: exception} do
    assert %BadMapError{term: ^secret} = exception
    basic_redaction_result = %BadMapError{term: SensitiveData.Redacted}

    # basic redaction
    assert ^basic_redaction_result = redact_exception(exception)

    # custom redaction
    redactor = fn val, type ->
      case type do
        :term ->
          {h, t} = String.split_at(val, 3)
          IO.iodata_to_binary([h, List.duplicate("*", String.length(t))])

        :args ->
          "*** redacted args ***"
      end
    end

    assert %BadMapError{term: "SOM********"} = redact_exception(exception, redactor)

    # handling failing custom redactions
    {redacted_exception, log} =
      with_log(fn -> redact_exception(exception, fn _val, _type -> raise "oops" end) end)

    assert ^basic_redaction_result = redacted_exception

    assert String.contains?(
             log,
             "Custom redaction strategy failed, falling back to `:strip` strategy"
           )
  end

  test "redact_stacktrace/2", %{secret: secret, stacktrace: stacktrace} do
    assert {Map, :get, [^secret, :some_key, nil]} = last_stacktrace_line(stacktrace)

    basic_redaction_result = {Map, :get, 3}

    # basic redaction
    assert ^basic_redaction_result = do_redact_stacktrace(stacktrace)

    # custom redaction
    redactor = fn args -> List.duplicate("🤫", length(args)) end
    assert {Map, :get, ["🤫", "🤫", "🤫"]} = do_redact_stacktrace(stacktrace, redactor)

    # handling failing custom redactions
    {redacted_stacktrace, log} =
      with_log(fn -> do_redact_stacktrace(stacktrace, fn _args -> raise "oops" end) end)

    assert ^basic_redaction_result = redacted_stacktrace

    assert String.contains?(
             log,
             "Custom redaction strategy failed, falling back to `:strip` strategy"
           )
  end

  # we only care about the last call (and drop the file info from the tuple)
  defp last_stacktrace_line(stacktrace), do: stacktrace |> hd() |> Tuple.delete_at(3)

  defp do_redact_stacktrace(stacktrace, strat \\ :strip) do
    stacktrace
    |> redact_stacktrace(strat)
    |> last_stacktrace_line()
  end
end
