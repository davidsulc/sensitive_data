defmodule SensitiveData.Redaction do
  @moduledoc """
  Functions for redacting information.

  In typical use, there's no need to call these functions directly:
  `SensitiveData.execute/1` should be used instead as it will handle
  redaction duties and call the necessary functions from this module.
  """

  alias SensitiveData.Redacted

  @doc """
  Prunes term and arguments from the given exception.

  ## Example

      iex> exception =
      ...>   try do
      ...>     Map.get("SOME SECRET", :some_key)
      ...>   rescue
      ...>     e -> e
      ...>   end
      %BadMapError{term: "SOME SECRET"}
      iex> SensitiveData.Redaction.prune_exception(exception)
      %BadMapError{term: SensitiveData.Redacted}
  """
  @spec prune_exception(map()) :: map()
  def prune_exception(e) when is_exception(e),
    do: e |> prune_term() |> prune_args()

  defp prune_term(%{term: _} = e), do: %{e | term: Redacted}
  defp prune_term(e), do: e

  defp prune_args(%{args: args} = e), do: %{e | args: List.duplicate(Redacted, length(args))}
  defp prune_args(e), do: e

  ############ Code taken from plug_crypto ########################################
  #
  # https://github.com/elixir-plug/plug_crypto/blob/a3162119fc8fe519772b74760ead4a89e7709925/lib/plug/crypto.ex#L11-L21
  # Licensed under the Apache License, Version 2.0 (the "License")
  #
  # No changes made
  #
  @doc """
  Prunes the stacktrace to remove any argument trace.
  """
  @spec prune_args_from_stacktrace(Exception.stacktrace()) :: Exception.stacktrace()
  def prune_args_from_stacktrace(stacktrace)

  def prune_args_from_stacktrace([{mod, fun, [_ | _] = args, info} | rest]),
    do: [{mod, fun, length(args), info} | rest]

  def prune_args_from_stacktrace(stacktrace) when is_list(stacktrace),
    do: stacktrace

  #
  ############ End code taken from plug_crypto ########################################
end
