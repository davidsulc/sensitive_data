defmodule SensitiveDataTest do
  use ExUnit.Case
  doctest SensitiveData

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
      capture_exception_io(fn -> SensitiveData.execute(test_action) end)

    refute String.contains?(error_message, secret)

    refute String.contains?(stacktrace, secret)
  end
end
