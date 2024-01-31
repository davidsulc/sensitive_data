defmodule SensitiveData.WrapperTest do
  use ExUnit.Case, async: true
  import ExUnitProperties

  import StreamData
  # this is the custom wrapper instance we'll be using to test
  import Wrappers.SensiData

  doctest SensitiveData.Wrapper

  test "wrap/unwrap yields original value" do
    check all(data <- term()) do
      assert data == data |> wrap() |> unwrap()
    end
  end
end
