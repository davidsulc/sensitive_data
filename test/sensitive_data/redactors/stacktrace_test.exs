defmodule SensitiveData.Redactors.StacktraceTest do
  use ExUnit.Case, async: true

  doctest SensitiveData.Redactors.Stacktrace

  import SensitiveData.Redactors.Stacktrace

  test "strip/1" do
    secret = "SOME SECRET"

    # test stacktrace redaction for exception with :term
    stacktrace =
      try do
        Map.get(secret, :some_key)
      rescue
        _ -> __STACKTRACE__
      end

    assert {Map, :get, [^secret, :some_key, nil]} = last_stacktrace_line(stacktrace)
    assert {Map, :get, 3} = strip(stacktrace) |> last_stacktrace_line()

    # test stacktrace redaction for exception with :args
    stacktrace =
      try do
        Wrappers.SensiData.map(secret, :foo)
      rescue
        _ -> __STACKTRACE__
      end

    assert {Wrappers.SensiData, :map, [^secret, :foo, []]} = last_stacktrace_line(stacktrace)
    assert {Wrappers.SensiData, :map, 3} = strip(stacktrace) |> last_stacktrace_line()

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

    assert ^orig_last_line = strip(stacktrace) |> last_stacktrace_line()
  end

  # we only care about the last call (and drop the file info from the tuple)
  defp last_stacktrace_line(stacktrace), do: stacktrace |> hd() |> Tuple.delete_at(3)
end
