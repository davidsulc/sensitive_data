defmodule SensitiveData.Redacted do
  @moduledoc """
  An empty module serving only to indicate that data has been redacted.

  This typically shows up in redacted exceptions and stack traces,
  as well as in cases where a `SensitiveData.Wrapper`'s custom `:redactor`
  function fails.
  """
end
