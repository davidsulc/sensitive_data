defmodule SensitiveData.DataType.NumberType do
  @moduledoc false

  keys = [:type]
  @enforce_keys keys
  defstruct keys

  def new!(float) when is_float(float) do
    %__MODULE__{
      type: :float
    }
  end

  def new!(integer) when is_integer(integer) do
    %__MODULE__{
      type: :integer
    }
  end
end
