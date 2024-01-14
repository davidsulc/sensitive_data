defmodule SensitiveData.Wrapper.ImplTest do
  use ExUnit.Case, async: true
  import ExUnitProperties

  import SensiData

  test "wrap/unwrap yields original value" do
    check all(data <- StreamData.term()) do
      assert data == data |> wrap() |> unwrap()
    end
  end
end
