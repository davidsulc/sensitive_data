defmodule SensitiveData.RedactionTest do
  use ExUnit.Case
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
    assert %BadMapError{term: SensitiveData.Redacted} = redact_exception(exception)

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

    {redacted_exception, log} =
      with_log(fn -> redact_exception(exception, fn _val, _type -> raise "oops" end) end)

    assert %BadMapError{term: SensitiveData.Redacted} = redacted_exception

    assert String.contains?(
             log,
             "Custom redaction strategy failed, falling back to `:strip` strategy"
           )
  end

  test "redact_args_from_stacktrace/2", %{secret: secret, stacktrace: stacktrace} do
    # we only care about the last call (and drop the file info from the tuple)
    show_last = fn stacktrace -> stacktrace |> hd() |> Tuple.delete_at(3) end

    assert {Map, :get, [^secret, :some_key, nil]} = show_last.(stacktrace)

    assert {Map, :get, 3} =
             stacktrace
             |> redact_args_from_stacktrace()
             |> show_last.()
  end
end
