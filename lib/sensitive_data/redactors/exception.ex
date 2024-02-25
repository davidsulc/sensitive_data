defmodule SensitiveData.Redactors.Exception do
  @moduledoc """
  Functions for redacting exceptions.

  > ### Tip {: .tip}
  >
  > You typically won't need to concern yourself with functions in this module,
  > as `SensitiveData.exec/2`, `c:SensitiveData.Wrapper.from/2`, and
  > friends, will use safe redaction implementations by default.
  """

  alias SensitiveData.RedactedException

  @doc """
  Replaces the exception with a fully redacted exception.

  ## Example

      iex(1)> e = ArgumentError.exception("foo")
      %ArgumentError{message: "foo"}
      iex(2)> SensitiveData.Redactors.Exception.drop(e)
      %SensitiveData.RedactedException{exception_name: ArgumentError}
  """
  @spec drop(Exception.t()) :: RedactedException.t()
  def drop(%name{} = e) when is_exception(e),
    do: RedactedException.exception(exception_name: name)
end
