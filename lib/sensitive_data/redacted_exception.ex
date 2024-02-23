defmodule SensitiveData.RedactedException do
  defexception [:exception_name]

  def message(%__MODULE__{exception_name: name}),
    do: "an exception of type `#{inspect(name)}` was raised in a sensitive context"
end
