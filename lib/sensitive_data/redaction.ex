defmodule SensitiveData.Redaction do
  @moduledoc """
  Functions for redacting information.

  > ### Tip {: .tip}
  >
  >In typical use, there's no need to call these functions directly:
  >`SensitiveData.exec/1` as well as the callbacks defined in `SensitiveData.Wrapper`
  >should be used instead as they will handle redaction duties upon failiure and call the
  >necessary functions from this module.
  """

  require Logger

  alias SensitiveData.Redacted

  @type exception_redaction_strategy :: exception_redactor_fun() | redaction_strategy_name()
  @type stacktrace_redaction_strategy :: stacktrace_redactor_fun() | redaction_strategy_name()

  @typedoc """
  Strategies:

  - `:strip` - terms and arguments are removed and replaced by the `SensitiveData.Redacted` atom

  Currently, only `:strip` is supported.
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
  @type stacktrace_redactor_fun :: (term() -> term())

  @doc """
  Redacts term and arguments from the given exception.

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
    redactor_fun =
      case redaction_strategy do
        :strip -> exception_redactor_from_strategy(:strip)
        fun when is_function(fun, 2) -> fun
      end

    try do
      redact_exception_with(e, redactor_fun)
    rescue
      _ ->
        log_custom_redaction_failed_error()
        redact_exception_with(e, exception_redactor_from_strategy(:strip))
    end
  end

  @spec redact_exception_with(Exception.t(), exception_redactor_fun()) :: Exception.t()
  defp redact_exception_with(e, redactor_fun) do
    e
    |> redactor(redactor_fun)
    |> redact_args(redactor_fun)
  end

  @spec redactor(Exception.t(), exception_redactor_fun()) :: Exception.t()

  defp redactor(%{term: term} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | term: redactor_fun.(term, :term)}

  defp redactor(e, _redactor_fun), do: e

  @spec redact_args(Exception.t(), exception_redactor_fun()) :: Exception.t()

  defp redact_args(%{args: args} = e, redactor_fun) when is_function(redactor_fun, 2),
    do: %{e | args: redactor_fun.(args, :args)}

  defp redact_args(e, _redactor_fun), do: e

  @spec exception_redactor_from_strategy(redaction_strategy_name()) :: exception_redactor_fun()
  defp exception_redactor_from_strategy(:strip), do: &strip/2

  defp strip(_term, :term), do: Redacted
  defp strip(args, :args), do: List.duplicate(Redacted, length(args))

  @doc """
  Redacts the stack trace to remove sensitive arguments.

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
      iex> redacted_stacktrace = SensitiveData.Redaction.redact_stacktrace(stacktrace)
      iex>
      iex> show_last = fn (stacktrace) -> stacktrace |> hd() |> Tuple.delete_at(3) end
      iex>
      iex> show_last.(stacktrace)
      {Map, :get, ["SOME SECRET", :some_key, nil]}
      iex>
      iex> show_last.(redacted_stacktrace)
      {Map, :get, 3}
      iex>
      iex> redactor = fn args ->
      ...>   if is_list(args) do
      ...>     List.duplicate("🤫", length(args))
      ...>   else
      ...>     "🤷‍♂️"
      ...>   end
      ...> end
      iex> redacted_stacktrace =
      ...>   SensitiveData.Redaction.redact_stacktrace(stacktrace, redactor)
      iex> show_last.(redacted_stacktrace)
      {Map, :get, ["🤫", "🤫", "🤫"]}
  """
  @spec redact_stacktrace(Exception.stacktrace(), stacktrace_redaction_strategy()) ::
          Exception.stacktrace()
  def redact_stacktrace(stacktrace, redaction_strategy \\ :strip) when is_list(stacktrace) do
    redactor =
      case redaction_strategy do
        fun when is_function(fun, 1) -> fun
        :strip -> stacktrace_redactor_from_strategy(:strip)
      end

    try do
      redact_stacktrace_with(stacktrace, redactor)
    rescue
      _ ->
        log_custom_redaction_failed_error()
        redact_stacktrace_with(stacktrace, stacktrace_redactor_from_strategy(:strip))
    end
  end

  @spec redact_stacktrace_with(Exception.stacktrace(), stacktrace_redactor_fun()) ::
          Exception.stacktrace()
  defp redact_stacktrace_with([{mod, fun, [_ | _] = args, info} | rest], redactor),
    do: [{mod, fun, redactor.(args), info} | rest]

  defp redact_stacktrace_with(stacktrace, _redactor), do: stacktrace

  @spec stacktrace_redactor_from_strategy(redaction_strategy_name()) :: stacktrace_redactor_fun()
  defp stacktrace_redactor_from_strategy(:strip) do
    fn args ->
      case args do
        list when is_list(list) -> length(list)
        _ -> args
      end
    end
  end

  defp log_custom_redaction_failed_error(),
    do: Logger.error("Custom redaction strategy failed, falling back to `:strip` strategy")
end
