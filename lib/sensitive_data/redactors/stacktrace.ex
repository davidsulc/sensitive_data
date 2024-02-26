defmodule SensitiveData.Redactors.Stacktrace do
  @moduledoc """
  Functions for redacting stack traces.

  > ### Tip {: .tip}
  >
  > You typically won't need to concern yourself with functions in this module,
  > as `SensitiveData.exec/2`, `c:SensitiveData.Wrapper.from/2`, and
  > friends, will use safe redaction implementations by default.
  """

  @doc """
  Redacts the argument list in the stack trace.

  ## Example

      iex(1)> stacktrace =
      ...(1)>   try do
      ...(1)>     Map.get("SOME SECRET", :some_key)
      ...(1)>   rescue
      ...(1)>     _ -> __STACKTRACE__
      ...(1)>   end
      iex(2)> true = match?([{Map, :get, ["SOME SECRET", :some_key, nil], _} | _], stacktrace)
      iex(3)> [_first_list | rest] = stacktrace
      iex(4)> redacted_stacktrace = SensitiveData.Redactors.Stacktrace.strip(stacktrace)
      iex(5)> true = match?([{Map, :get, 3, _} | ^rest], redacted_stacktrace)
  """

  def strip([{mod, fun, args, info} | rest]) when is_list(args),
    do: [{mod, fun, length(args), info} | rest]

  def strip(stacktrace), do: stacktrace
end
