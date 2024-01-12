defmodule SensitiveData.Redaction do
  @moduledoc """
  Functions for redacting information.

  > ### Tip {: .tip}
  >
  >In typical use, there's no need to call these functions directly:
  >`SensitiveData.execute/1` should be used instead as it will handle
  >redaction duties and call the necessary functions from this module.
  """

  alias SensitiveData.Redacted

  @type exception_pruning_strategy :: exception_redactor_fun() | pruning_strategy_name()
  @type stracktrace_pruning_strategy :: stacktrace_redactor_fun() | pruning_strategy_name()
  @typedoc """
  The name of the pruning strategy to use when pruning `term` and `args`
  values from `Exception`s. Currently, only `:strip` is supported.
  """
  @type pruning_strategy_name :: :strip
  @typedoc """
  A function responsible for redacting term and args.
  It will be given a value to redact, as well whether the value came
  from the `:term` or `:args` key within the `Exception` struct.
  The function must return a redacted version of the provided value.
  """
  @type exception_redactor_fun :: (term(), value_type() -> term())
  @typedoc "The type of information being pruned from the `Exception`"
  @type value_type :: :term | :args
  @typedoc """
  A function responsible for redacting args from a stacktrace.
  It will be given the value in the 3rd position of the tuple in the
  stacktrace (i.e., `elem(2)`).
  The function must return a redacted version of the provided value.
  """
  @type stacktrace_redactor_fun :: (term(), value_type() -> term())

  @doc """
  Prunes term and arguments from the given exception.

  > #### Beware {: .warning}
  >
  > If you use a custom pruning strategy, you must ensure it won't leak any
  > sensitive data under any circumstances.

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
  @spec prune_exception(Exception.t(), exception_pruning_strategy()) :: Exception.t()
  def prune_exception(e, pruning_strategy \\ :strip) when is_exception(e) do
    # TODO FIXME: handle case where provided value is invalid (not :strip or function w/ 2 arity)
    # TODO FIXME: handle crashes in custom redactor
    redactor_fun =
      case pruning_strategy do
        :strip -> &strip/2
        fun when is_function(fun, 2) -> fun
      end

    e
    |> prune_term(redactor_fun)
    |> prune_args(redactor_fun)
  end

  @spec prune_term(Exception.t(), exception_redactor_fun()) :: Exception.t()

  defp prune_term(%{term: term} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | term: redactor_fun.(term, :term)}

  defp prune_term(e, _redactor_fun), do: e

  @spec prune_args(Exception.t(), exception_redactor_fun()) :: Exception.t()

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
  # Changes made:
  # - add extra parameter to allow for custom redaction of arguments
  #
  @doc """
  Prunes the stacktrace to remove sensitive arguments.

  By default, all arguments will be completely stripped.

  > #### Beware {: .warning}
  >
  > If you use a custom pruning strategy, you must ensure it won't leak any
  > sensitive data under any circumstances.

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
      iex>
      iex> redactor = fn args -> List.duplicate("🤫", length(args)) end
      iex> redacted_stacktrace =
      ...>   SensitiveData.Redaction.prune_args_from_stacktrace(stacktrace, redactor)
      iex> show_last.(redacted_stacktrace)
      {Map, :get, ["🤫", "🤫", "🤫"]}
  """
  @spec prune_args_from_stacktrace(Exception.stacktrace(), stracktrace_pruning_strategy()) ::
          Exception.stacktrace()
  def prune_args_from_stacktrace(stacktrace, pruning_strategy \\ :strip)

  def prune_args_from_stacktrace([{mod, fun, [_ | _] = args, info} | rest], pruning_strategy) do
    # TODO FIXME: handle case where provided value is invalid (not :strip or function w/ 1 arity)
    # TODO FIXME: handle crashes in custom redactor
    redactor =
      case pruning_strategy do
        fun when is_function(fun, 1) ->
          fun

        :strip ->
          fn args ->
            case args do
              list when is_list(list) -> length(list)
              _ -> args
            end
          end
      end

    [{mod, fun, redactor.(args), info} | rest]
  end

  def prune_args_from_stacktrace(stacktrace, _pruning_strategy) when is_list(stacktrace),
    do: stacktrace

  #
  ############ End code taken from plug_crypto ########################################
end
