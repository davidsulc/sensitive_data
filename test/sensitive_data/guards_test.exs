defmodule SensitiveData.GuardsTest do
  use ExUnit.Case

  import SensitiveData.Guards

  test "functions allowable in guards" do
    case Demo.wrap([1, 2, 3]) do
      data when is_sensitive_list(data) -> :ok
      _ -> flunk("is_sensitive_list guard failed to work properly")
    end
  end
end
