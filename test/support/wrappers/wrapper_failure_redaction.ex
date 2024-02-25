defmodule Wrappers.FailureRedaction do
  use SensitiveData.Wrapper,
    exception_redactor: :exception_redactor,
    stacktrace_redactor: :stacktrace_redactor

  def exception_redactor(e) do
    send(self(), {:exception_redactor, e})
    e
  end

  def stacktrace_redactor(s) do
    send(self(), {:stacktrace_redactor, s})
    s
  end
end
