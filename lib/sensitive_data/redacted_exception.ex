defmodule SensitiveData.RedactedException do
  @moduledoc """
  A fully redacted exception.

  This is used to replace exceptions raised in a sensitive context,
  such as within `SensitiveData.exec/2`.
  """
  defexception [:exception_name]

  @type t() :: %__MODULE__{exception_name: module()}

  def message(%__MODULE__{exception_name: name}),
    do: "an exception of type `#{inspect(name)}` was raised in a sensitive context"
end
