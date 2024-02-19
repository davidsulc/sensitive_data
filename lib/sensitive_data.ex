defmodule SensitiveData do
  @moduledoc """
  Documentation for `SensitiveData`.

  This library aims to provide easy and convenient functionality to make following
  the [Erlang Ecosystem Foundation](https://erlef.org/)'s recommendations regarding
  [protecting sensitive data](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data.html)
  more convenient, thereby making it less likely that sensitive data is mishandled.

  While wrapping sensitive data within a `SensitiveData.Wrapper` instance will
  conform to many recommendations in the article (wrapping sensitive data in
  a closure, pruning stack traces and exception structs, deriving the
  `Inspect` protocol), it doesn't cover others which may be relevant to your
  situation (such as using the [:private option](https://erlang.org/doc/man/ets.html#new-2)
  for ETS tables containing sensitive data, flagging the current process as
  sensitive using [:erlang.process_flag(:sensitive, true)](https://erlang.org/doc/man/erlang.html#process_flag-2)
  in processes holding sensitive data or application logic, and so on).
  """

  alias SensitiveData.Redaction
  alias SensitiveData.Wrapper

  @type exec_opts :: [
          exception_redaction: Redaction.exception_redaction_strategy(),
          stacktrace_redaction: Redaction.stacktrace_redaction_strategy(),
          into: Wrapper.spec()
        ]

  @doc ~s"""
  Executes the provided function, ensuring no data leaks in case of error.

  ## Options

  - `:exception_redaction` - will be passed on to
    `SensitiveData.Redaction.redact_exception/2`
  - `:stacktrace_redaction` - will be passed on to
    `SensitiveData.Redaction.redact_stacktrace/2`
  - `:into` - a `t:SensitiveData.Wrapper.spec/0` value into which the `fun` execution
    result should be wrapped.

  ## Examples

      iex> Map.get("SOME_PASSWORD", :foobar)
      ** (BadMapError) expected a map, got: "SOME_PASSWORD"

      iex> SensitiveData.exec(fn ->
      ...>   Map.get("SOME_PASSWORD", :foobar)
      ...> end)
      ** (BadMapError) expected a map, got: SensitiveData.Redacted

      iex> SensitiveData.exec(fn ->
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

  Passing the execution result to a `SecretData` module implementing
  the `SensitiveData.Wrapper` behaviour:

      SensitiveData.exec(fn ->
        System.fetch_env!("DATABASE_PASSWORD")
      end, into: SecretData)
  """
  @spec exec((-> result), exec_opts()) :: result when result: term() | no_return()
  def exec(fun, opts \\ []) when is_function(fun, 0) and is_list(opts) do
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

  @doc ~s"""
  Reads a line from stdin, without echoing the input back to the console.

  ## Options

  - `:into` - a `t:SensitiveData.Wrapper.spec/0` value into which the input should
    be wrapped. By default, the input is not wrapped and is returned as-is, similarly
    to `IO.gets/2`.

  ## Examples

  To display a prompt and await user input:

      SensitiveData.gets_sensitive("Enter your database password: ")

  To do the same but wrap the result within a `SecretData` module implementing
  the `SensitiveData.Wrapper` behaviour:

      SensitiveData.gets_sensitive("Enter your database password: ",
        into: {SecretData, label: :db_password})
  """
  @spec gets_sensitive(prompt, into: Wrapper.spec()) :: user_input
        when prompt: String.t(), user_input: String.t()
  def gets_sensitive(prompt, opts \\ []) do
    exec(fn ->
      SensitiveData.IO.gets_sensitive(prompt)
      |> maybe_wrap(opts)
    end)
  end

  defp maybe_wrap(raw_data, opts) do
    case Keyword.get(opts, :into) do
      nil -> raw_data
      into -> Wrapper.Impl.from(fn -> raw_data end, into: into)
    end
  end
end
