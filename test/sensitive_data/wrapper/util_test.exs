defmodule SensitiveData.Wrapper.UtilTest do
  use ExUnit.Case
  import ExUnitProperties

  import StreamData
  import SensitiveData.Wrapper.Util

  doctest SensitiveData.Wrapper.Util

  test "sensitive_length/1" do
    check all(list <- list_of(term())) do
      assert list |> SensiData.wrap() |> sensitive_length() == length(list)
    end
  end

  test "sensitive_map_size/1" do
    check all(map <- map_of(term(), term())) do
      assert map |> SensiData.wrap() |> sensitive_map_size() == map_size(map)
    end
  end

  test "sensitive_tuple_size/1" do
    check all(tuple <- bind(list_of(term()), fn list -> constant(List.to_tuple(list)) end)) do
      assert tuple |> SensiData.wrap() |> sensitive_tuple_size() == tuple_size(tuple)
    end
  end
end
