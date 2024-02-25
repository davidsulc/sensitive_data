defmodule SensitiveData.Redaction do
  @moduledoc "Utilities for redacting information from exceptions and stack traces."

  require Logger

  alias SensitiveData.InvalidIntoOptionError

  @type redactor(type) :: (original :: type -> redacted :: type)

  @typedoc """
  A function responsible for redacting exceptions.

  The function must return a redacted version of the provided exception.

  If this function fails, redaction will fall back to
  `SensitiveData.Redactors.Exception.drop/1`.

  > #### Beware {: .warning}
  >
  > If you use a custom exception redaction strategy, you must ensure it won't leak sensitive
  > information for any possible exception provided as the argument.
  >
  > Bear in mind you must handle not only standard Elixir exceptions and those from your code
  > base, but also any exception that may be raised by any dependency.
  """
  @type exception_redactor :: redactor(Exception.t())

  @typedoc """
  A function responsible for redacting a stacktrace.

  The function must return a redacted version of the provided stack trace.

  If this function fails, redaction will fall back to
  `SensitiveData.Redactors.Stacktrace.strip/1`.

  > #### Beware {: .warning}
  >
  > If you use a custom stack trace redaction strategy, you must ensure it won't leak sensitive
  > data under any circumstances.
  """
  @type stacktrace_redactor :: redactor(Exception.stacktrace())

  @doc false
  # Redacts the exception according to the provided redactor.
  # we don't want to redact "internal errors" as
  # - we know they don't leak sensitive data
  # - we want users to know what went wrong in their use of this library so they can fix it
  @spec redact_exception(Exception.t(), exception_redactor()) :: Exception.t()

  def redact_exception(%InvalidIntoOptionError{}, _redactor) do
    ArgumentError.exception(message: "provided `:into` opts did not result in a valid wrapper")
  end

  def redact_exception(e, redactor) when is_exception(e) and is_function(redactor, 1) do
    try do
      redactor.(e)
    rescue
      _ ->
        log_custom_redaction_failed_error("exception")
        SensitiveData.Redactors.Exception.drop(e)
    end
  end

  @doc false
  # Redacts the stack trace with the provided redactor.
  @spec redact_stacktrace(Exception.stacktrace(), stacktrace_redactor()) ::
          Exception.stacktrace()
  def redact_stacktrace(stacktrace, redactor) when is_list(stacktrace) do
    try do
      redactor.(stacktrace)
    rescue
      _ ->
        log_custom_redaction_failed_error("stack trace")
        SensitiveData.Redactors.Stacktrace.strip(stacktrace)
    end
  end

  defp log_custom_redaction_failed_error(type) when is_binary(type),
    do: Logger.error("Custom #{type} redaction strategy failed, using default redactor")
end
