defmodule SensitiveData do
  @moduledoc """
  This library aims to make [Data Leak Prevention](data_leak_prevention.html)
  straightforward and convenient, by making it easy to follow most of the
  [Erlang Ecosystem Foundation](https://erlef.org/)'s recommendations regarding
  [protecting sensitive data](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data.html).

  For a quick overview, take a look at the [Getting Started](getting_started.html)
  and [Cheatsheet](cheatsheet.html) pages.

  While wrapping sensitive data within a `SensitiveData.Wrapper` instance will
  conform to many recommendations in the linked article (such as wrapping sensitive data in
  a closure, pruning stack traces, and deriving the
  `Inspect` protocol), it doesn't cover others which may be relevant to your
  situation (such as using the [:private option](https://erlang.org/doc/man/ets.html#new-2)
  for ETS tables containing sensitive data, flagging the current process as
  sensitive using [:erlang.process_flag(:sensitive, true)](https://erlang.org/doc/man/erlang.html#process_flag-2)
  in processes holding sensitive data, and so on).
  """

  alias SensitiveData.Redaction
  alias SensitiveData.Redactors
  alias SensitiveData.Wrapper

  @type exec_opts :: [
          into: Wrapper.spec(),
          exception_redactor: Redaction.exception_redactor(),
          stacktrace_redactor: Redaction.stacktrace_redactor()
        ]

  @doc ~s"""
  Executes the provided function, ensuring no data leaks in case of error.

  ## Options

  - `:into` - a `t:SensitiveData.Wrapper.spec/0` value into which the `fun` execution
    result should be wrapped.
  - `:exception_redactor` - the `t:SensitiveData.Redaction.exception_redactor/0`
    to use when redacting an `t:Exception.t/0`. Defaults to
    `SensitiveData.Redactors.Exception.drop/1`, which is also the fallback if
    the custom redactor fails. See
    [Custom Failure Redaction](SensitiveData.Wrapper.html#module-custom-failure-redaction).
  - `:stacktrace_redactor` - the `t:SensitiveData.Redaction.stacktrace_redactor/0`
    to use when redacting a stack trace. Defaults to
    `SensitiveData.Redactors.Stacktrace.strip/1`, which is also the fallback if
    the custom redactor fails. See
    [Custom Failure Redaction](SensitiveData.Wrapper.html#module-custom-failure-redaction).

  ## Examples

      iex> Map.get("SOME_PASSWORD", :foobar)
      ** (BadMapError) expected a map, got: "SOME_PASSWORD"

      iex> SensitiveData.exec(fn ->
      ...>   Map.get("SOME_PASSWORD", :foobar)
      ...> end)
      ** (SensitiveData.RedactedException) an exception of type `BadMapError` was raised in a sensitive context

  Passing the execution result to a `SecretData` module implementing
  the `SensitiveData.Wrapper` behaviour:

      SensitiveData.exec(fn ->
        System.fetch_env!("DATABASE_PASSWORD")
      end, into: SecretData)
      #SecretData<...>
  """
  @spec exec((-> result), exec_opts()) :: result when result: term() | Wrapper.t() | no_return()
  def exec(fun, opts \\ []) when is_function(fun, 0) and is_list(opts) do
    raw_data =
      try do
        fun.()
      rescue
        e ->
          exception_redactor =
            Keyword.get(opts, :exception_redactor, &Redactors.Exception.drop/1)

          stacktrace_redactor =
            Keyword.get(opts, :stacktrace_redactor, &Redactors.Stacktrace.strip/1)

          reraise Redaction.redact_exception(e, exception_redactor),
                  Redaction.redact_stacktrace(__STACKTRACE__, stacktrace_redactor)
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
        into: SecretData)
  """
  @spec gets_sensitive(prompt, list({:into, Wrapper.spec()})) :: user_input | Wrapper.t()
        when prompt: String.t(), user_input: String.t()
  def gets_sensitive(prompt, opts \\ []) do
    SensitiveData.IO.gets_sensitive(prompt)
    |> maybe_wrap(opts)
  end

  defp maybe_wrap(raw_data, opts) do
    case Keyword.get(opts, :into) do
      nil -> raw_data
      into -> Wrapper.Impl.from(fn -> raw_data end, into: into)
    end
  end
end
