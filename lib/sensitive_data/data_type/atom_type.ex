defmodule SensitiveData.DataType.AtomType do
  @moduledoc false

  keys = [:is_boolean, :is_nil]
  @enforce_keys keys
  defstruct keys

  def new!(nil) do
    %__MODULE__{
      is_nil: true,
      is_boolean: false
    }
  end

  def new!(boolean) when is_boolean(boolean) do
    %__MODULE__{
      is_boolean: true,
      is_nil: false
    }
  end

  def new!(atom) when is_atom(atom) do
    %__MODULE__{
      is_boolean: false,
      is_nil: false
    }
  end
end
