defmodule SensitiveDataTest do
  use ExUnit.Case
  doctest SensitiveData

  import SensitiveData

  defp capture_exception_io(fun) do
    try do
      fun.()
    rescue
      e -> {inspect(e), inspect(__STACKTRACE__)}
    end
  end

  test "execute/1" do
    secret = "SECRET"
    test_action = fn -> Map.get(secret, :bad_key) end

    # secrets leak normally
    {error_message, stacktrace} = capture_exception_io(test_action)

    assert String.contains?(error_message, secret)

    assert String.contains?(stacktrace, secret)

    # secrets don't leak from within `execute`
    {error_message, stacktrace} =
      capture_exception_io(fn -> execute(test_action) end)

    refute String.contains?(error_message, secret)

    refute String.contains?(stacktrace, secret)

    # redaction can be customized
    custom_redaction_exception = "CUSTOM_REDACTION_EXCEPTION"
    custom_redaction_stacktrace = "CUSTOM_REDACTION_STACKTRACE"

    {error_message, stacktrace} =
      capture_exception_io(fn ->
        execute(test_action,
          exception_redaction: fn _val, _term -> custom_redaction_exception end,
          stacktrace_redaction: fn _args -> custom_redaction_stacktrace end
        )
      end)

    assert String.contains?(error_message, custom_redaction_exception)
    assert String.contains?(stacktrace, custom_redaction_stacktrace)

    refute String.contains?(error_message, secret)
    refute String.contains?(stacktrace, secret)
  end
end
