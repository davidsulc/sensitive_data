defmodule SensitiveData.Redaction do
  @moduledoc false
  # Functions for redacting information from exceptions and stack traces.

  require Logger

  alias SensitiveData.InvalidIntoOptionError

  @typedoc """
  A function responsible for redacting exceptions.

  The function must return a redacted version of the provided exception.
  """
  @type exception_redactor :: (unredacted_exception :: struct() -> redacted_exception :: struct())

  @typedoc """
  A function responsible for redacting a stacktrace.

  The function must return a redacted version of the provided stack trace.
  """
  @type stacktrace_redactor :: (Exception.stacktrace() -> Exception.stacktrace())

  @doc """
  Redacts the exception according to the provided redactor.
  """

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
        log_custom_redaction_failed_error()
        SensitiveData.Redactors.Exception.drop(e)
    end
  end

  @doc """
  Redacts the stack trace with the provided redactor.
  """
  @spec redact_stacktrace(Exception.stacktrace(), stacktrace_redactor()) ::
          Exception.stacktrace()
  def redact_stacktrace(stacktrace, redactor) when is_list(stacktrace) do
    try do
      redactor.(stacktrace)
    rescue
      _ ->
        log_custom_redaction_failed_error()
        SensitiveData.Redactors.Stacktrace.strip(stacktrace)
    end
  end

  defp log_custom_redaction_failed_error(),
    do: Logger.error("Custom redaction strategy failed, using default redactor")
end
