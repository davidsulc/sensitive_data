defmodule SensitiveData.DataType.MapType do
  @moduledoc false

  keys = [:name, :size, :is_exception]
  @enforce_keys keys
  defstruct keys

  def new!(map) when is_map(map) do
    name =
      case map do
        %name{} -> name
        _ -> nil
      end

    struct!(__MODULE__, size: map_size(map), is_exception: is_exception(map), name: name)
  end
end
