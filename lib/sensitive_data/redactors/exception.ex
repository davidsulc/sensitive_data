defmodule SensitiveData.Redactors.Exception do
  alias SensitiveData.RedactedException

  def drop(%name{} = e) when is_exception(e),
    do: RedactedException.exception(exception_name: name)
end
