defmodule SensitiveData.Redaction do
  @moduledoc """
  Functions for redacting information.

  In typical use, there's no need to call these functions directly:
  `SensitiveData.execute/1` should be used instead as it will handle
  redaction duties and call the necessary functions from this module.
  """

  alias SensitiveData.Redacted

  @type pruning_strategy :: redactor_fun() | pruning_strategy_name()
  @typedoc """
  A function responsible for redacting term and args.
  It will be given a value to redact, as well whether the value came
  from the `:term` or `:args` key within the `Exception` struct.
  The function must return a redacted version of the provided value.
  """
  @type redactor_fun :: (term(), value_type() -> term())
  @typedoc """
  The name of the pruning strategy to use when pruning `term` and `args`
  values from `Exception`s. Currently, only `:strip` is supported.
  """
  @type pruning_strategy_name :: :strip
  @typedoc "The type of information being pruned from the `Exception`"
  @type value_type :: :term | :args

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
      iex> SensitiveData.Redaction.prune_exception(exception, fn val, type ->
      ...>   case type do
      ...>     :term ->
      ...>       {h, t} = String.split_at(val, 3)
      ...>       IO.iodata_to_binary([h, List.duplicate("*", String.length(t))])
      ...>     :args -> "*** redacted args ***"
      ...>   end
      ...> end)
      %BadMapError{term: "SOM********"}
  """
  @spec prune_exception(Exception.t(), pruning_strategy()) :: Exception.t()
  def prune_exception(e, pruning_strategy \\ :strip) when is_exception(e) do
    redactor_fun =
      case pruning_strategy do
        :strip -> &strip/2
        fun when is_function(fun, 2) -> fun
      end

    e
    |> prune_term(redactor_fun)
    |> prune_args(redactor_fun)
  end

  @spec prune_term(Exception.t(), redactor_fun()) :: Exception.t()

  defp prune_term(%{term: term} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | term: redactor_fun.(term, :term)}

  defp prune_term(e, _redactor_fun), do: e

  @spec prune_args(Exception.t(), redactor_fun()) :: Exception.t()

  defp prune_args(%{args: args} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | args: redactor_fun.(args, :args)}

  defp prune_args(e, _redactor_fun), do: e

  defp strip(_term, :term), do: Redacted
  defp strip(args, :args), do: List.duplicate(Redacted, length(args))

  ############ Code taken from plug_crypto ########################################
  #
  # https://github.com/elixir-plug/plug_crypto/blob/a3162119fc8fe519772b74760ead4a89e7709925/lib/plug/crypto.ex#L11-L21
  # Licensed under the Apache License, Version 2.0 (the "License")
  #
  # No changes made
  #
  @doc """
  Prunes the stacktrace to remove any argument trace.

  ## Example

      iex> stacktrace =
      ...>   try do
      ...>     Map.get("SOME SECRET", :some_key)
      ...>   rescue
      ...>     _ -> __STACKTRACE__
      ...>   end
      iex> redacted_stacktrace = SensitiveData.Redaction.prune_args_from_stacktrace(stacktrace)
      iex>
      iex> show_last = fn (stacktrace) -> stacktrace |> hd() |> Tuple.delete_at(3) end
      iex>
      iex> show_last.(stacktrace)
      {Map, :get, ["SOME SECRET", :some_key, nil]}
      iex>
      iex> show_last.(redacted_stacktrace)
      {Map, :get, 3}
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
