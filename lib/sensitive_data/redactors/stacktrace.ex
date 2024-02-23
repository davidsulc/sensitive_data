defmodule SensitiveData.Redactors.Stacktrace do
  def strip([{mod, fun, args, info} | rest]) when is_list(args),
    do: [{mod, fun, length(args), info} | rest]

  def strip(stacktrace), do: stacktrace
end
