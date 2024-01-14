defmodule SensitiveData do
  @moduledoc """
  Documentation for `SensitiveData`.
  """

  alias SensitiveData.Redaction
  alias SensitiveData.Wrapper

  @doc """
  Executes the provided function, ensuring no data leaks in case of error.

  ## Options

  - `:exception_redaction`: value that will be passed on to `SensitiveData.Redaction.redact_exception/2`
  - `:stacktrace_redaction`: value that will be passed on to `SensitiveData.Redaction.redact_stacktrace/2`

  ## Examples

      iex> Map.get("SOME_PASSWORD", :foobar)
      ** (BadMapError) expected a map, got: "SOME_PASSWORD"

      iex> SensitiveData.execute(fn ->
      ...>   Map.get("SOME_PASSWORD", :foobar)
      ...> end)
      ** (BadMapError) expected a map, got: SensitiveData.Redacted

      iex> SensitiveData.execute(fn ->
      ...>     Map.get("SOME_PASSWORD", :foobar)
      ...>   end,
      ...>   exception_redaction: fn val, :term ->
      ...>     case is_binary(val) do
      ...>       true ->
      ...>         [h | t] = String.split(val, "", trim: true)
      ...>         IO.iodata_to_binary([h, String.duplicate("*", length(t))])
      ...>
      ...>       false ->
      ...>         SensitiveData.Redacted
      ...>   end
      ...> end)
      ** (BadMapError) expected a map, got: "S************"
  """
  # TODO document :into option
  @spec execute((-> result), Keyword.t()) :: result when result: term() | no_return()
  def execute(fun, opts \\ []) when is_function(fun, 0) and is_list(opts) do
    raw_data =
      try do
        fun.()
      rescue
        e ->
          exception_opts = Keyword.get(opts, :exception_redaction, :strip)
          stacktrace_opts = Keyword.get(opts, :stacktrace_redaction, :strip)

          reraise Redaction.redact_exception(e, exception_opts),
                  Redaction.redact_stacktrace(__STACKTRACE__, stacktrace_opts)
      end

    maybe_wrap(raw_data, opts)
  end

  @doc """
  Reads a line from stdin, without echoing the input back to the console.

  ## Examples

  To display "Enter your password: " as a prompt and await user input:

      SensitiveData.get_sensitive("Enter your password: ")
  """
  # TODO document :into option
  @spec gets_sensitive(prompt, Keyword.t()) :: user_input
        when prompt: String.t(), user_input: String.t()
  def gets_sensitive(prompt, opts \\ []) do
    execute(fn ->
      SensitiveData.IO.gets_sensitive(prompt)
      |> maybe_wrap(opts)
    end)
  end

  defp maybe_wrap(raw_data, opts) do
    case Keyword.get(opts, :into) do
      nil -> raw_data
      into -> Wrapper.Impl.wrap(raw_data, into: into)
    end
  end
end
