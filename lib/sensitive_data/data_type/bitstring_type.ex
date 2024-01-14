defmodule SensitiveData.DataType.BitstringType do
  @moduledoc false

  keys = [:is_binary]
  @enforce_keys keys
  defstruct keys

  def new!(bitstring) when is_bitstring(bitstring) do
    %__MODULE__{
      is_binary: is_binary(bitstring)
    }
  end
end
