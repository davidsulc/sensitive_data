defmodule SensitiveData.Redaction do
  @moduledoc """
  Functions for redacting information.

  > ### Tip {: .tip}
  >
  >In typical use, there's no need to call these functions directly:
  >`SensitiveData.execute/1` should be used instead as it will handle
  >redaction duties and call the necessary functions from this module.
  """

  require Logger

  alias SensitiveData.Redacted

  @type exception_redaction_strategy :: exception_redactor_fun() | redaction_strategy_name()
  @type stracktrace_redaction_strategy :: stacktrace_redactor_fun() | redaction_strategy_name()
  @typedoc """
  The name of the redaction strategy to use when redaction `term` and `args`
  values from `Exception`s. Currently, only `:strip` is supported.
  """
  @type redaction_strategy_name :: :strip
  @typedoc """
  A function responsible for redacting term and args.
  It will be given a value to redact, as well whether the value came
  from the `:term` or `:args` key within the `Exception` struct.
  The function must return a redacted version of the provided value.
  """
  @type exception_redactor_fun :: (term(), value_type() -> term())
  @typedoc "The type of information being redacted from the `Exception`"
  @type value_type :: :term | :args
  @typedoc """
  A function responsible for redacting args from a stacktrace.
  It will be given the value in the 3rd position of the tuple in the
  stacktrace (i.e., `elem(2)`).
  The function must return a redacted version of the provided value.
  """
  @type stacktrace_redactor_fun :: (term(), value_type() -> term())

  @doc """
  redacts term and arguments from the given exception.

  > #### Beware {: .warning}
  >
  > If you use a custom redaction strategy, you must ensure it won't leak any
  > sensitive data under any circumstances.

  ## Example

      iex> exception =
      ...>   try do
      ...>     Map.get("SOME SECRET", :some_key)
      ...>   rescue
      ...>     e -> e
      ...>   end
      %BadMapError{term: "SOME SECRET"}
      iex> SensitiveData.Redaction.redact_exception(exception)
      %BadMapError{term: SensitiveData.Redacted}
      iex> SensitiveData.Redaction.redact_exception(exception, fn val, type ->
      ...>   case type do
      ...>     :term ->
      ...>       {h, t} = String.split_at(val, 3)
      ...>       IO.iodata_to_binary([h, List.duplicate("*", String.length(t))])
      ...>     :args -> "*** redacted args ***"
      ...>   end
      ...> end)
      %BadMapError{term: "SOM********"}
  """
  @spec redact_exception(Exception.t(), exception_redaction_strategy()) :: Exception.t()
  def redact_exception(e, redaction_strategy \\ :strip) when is_exception(e) do
    # TODO FIXME: handle case where provided value is invalid (not :strip or function w/ 2 arity)
    # TODO FIXME: handle crashes in custom redactor
    redactor_fun =
      case redaction_strategy do
        :strip -> redactor_from_strategy(:strip)
        fun when is_function(fun, 2) -> fun
      end

    try do
      redact_with(e, redactor_fun)
    rescue
      _ ->
        Logger.error("Custom redaction strategy failed, falling back to `:strip` strategy")
        redact_with(e, redactor_from_strategy(:strip))
    end
  end

  @spec redact_with(Exception.t(), exception_redactor_fun()) :: Exception.t()
  defp redact_with(e, redactor_fun) do
    e
    |> redact_term(redactor_fun)
    |> redact_args(redactor_fun)
  end

  @spec redact_term(Exception.t(), exception_redactor_fun()) :: Exception.t()

  defp redact_term(%{term: term} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | term: redactor_fun.(term, :term)}

  defp redact_term(e, _redactor_fun), do: e

  @spec redact_args(Exception.t(), exception_redactor_fun()) :: Exception.t()

  defp redact_args(%{args: args} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | args: redactor_fun.(args, :args)}

  defp redact_args(e, _redactor_fun), do: e

  @spec redactor_from_strategy(redaction_strategy_name()) :: exception_redactor_fun()
  defp redactor_from_strategy(:strip), do: &strip/2

  defp strip(_term, :term), do: Redacted
  defp strip(args, :args), do: List.duplicate(Redacted, length(args))

  @doc """
  redacts the stacktrace to remove sensitive arguments.

  By default, all arguments will be completely stripped.

  > #### Beware {: .warning}
  >
  > If you use a custom redaction strategy, you must ensure it won't leak any
  > sensitive data under any circumstances.

  ## Example

      iex> stacktrace =
      ...>   try do
      ...>     Map.get("SOME SECRET", :some_key)
      ...>   rescue
      ...>     _ -> __STACKTRACE__
      ...>   end
      iex> redacted_stacktrace = SensitiveData.Redaction.redact_args_from_stacktrace(stacktrace)
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
      ...>   SensitiveData.Redaction.redact_args_from_stacktrace(stacktrace, redactor)
      iex> show_last.(redacted_stacktrace)
      {Map, :get, ["🤫", "🤫", "🤫"]}
  """
  @spec redact_args_from_stacktrace(Exception.stacktrace(), stracktrace_redaction_strategy()) ::
          Exception.stacktrace()
  def redact_args_from_stacktrace(stacktrace, redaction_strategy \\ :strip)

  def redact_args_from_stacktrace([{mod, fun, [_ | _] = args, info} | rest], redaction_strategy) do
    # TODO FIXME: handle case where provided value is invalid (not :strip or function w/ 1 arity)
    # TODO FIXME: handle crashes in custom redactor
    redactor =
      case redaction_strategy do
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

  def redact_args_from_stacktrace(stacktrace, _redaction_strategy) when is_list(stacktrace),
    do: stacktrace
end
