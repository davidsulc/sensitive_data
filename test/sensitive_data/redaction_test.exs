defmodule SensitiveData.RedactionTest do
  use ExUnit.Case, async: true
  import ExUnitProperties

  import ExUnit.CaptureLog, only: [capture_log: 1]
  import SensitiveData.Redaction

  alias Support.Exceptions

  @internal_errors [
    SensitiveData.InvalidIntoOptionError
  ]

  defp fake_redactor(term, ref) when is_reference(ref) do
    me = self()
    send(me, {ref, term})
    term
  end

  test "redact_exception/2" do
    check all(exception <- Exceptions.exception()) do
      ref = make_ref()
      redact_exception(exception, &fake_redactor(&1, ref))

      assert_received({^ref, ^exception})
    end
  end

  test "redact_exception/2 with failing custom redaction" do
    exception = Exceptions.exception() |> Enum.take(1) |> hd()

    log =
      capture_log(fn ->
        redacted_exception =
          redact_exception(exception, fn _ -> raise "failed custom redaction" end)

        assert is_exception(redacted_exception, SensitiveData.RedactedException)
      end)

    assert String.contains?(log, "Custom redaction strategy failed, using default redactor")
  end

  test "redact_exception/2 converts all internal errors into ArgumentError" do
    for error_mod <- @internal_errors do
      exception = error_mod.exception([])
      ref = make_ref()

      redacted_exception = redact_exception(exception, &fake_redactor(&1, ref))

      assert is_exception(redacted_exception, ArgumentError)

      refute_received({^ref, ^exception})
    end
  end

  test "redact_stacktrace/2" do
    check all(exception <- Exceptions.exception()) do
      ref = make_ref()

      stacktrace =
        try do
          raise exception
        rescue
          _ ->
            stacktrace = __STACKTRACE__
            redact_stacktrace(stacktrace, &fake_redactor(&1, ref))
            stacktrace
        end

      assert_received({^ref, ^stacktrace})
    end
  end

  test "redact_stacktrace/2 with failing custom redaction" do
    exception = Exceptions.exception() |> Enum.take(1) |> hd()

    log =
      capture_log(fn ->
        try do
          raise exception
        rescue
          _ ->
            redact_stacktrace(__STACKTRACE__, fn _ -> raise "failed custom redaction" end)
        end
      end)

    assert String.contains?(log, "Custom redaction strategy failed, using default redactor")
  end
end
