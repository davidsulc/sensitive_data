defmodule SensitiveDataTest do
  use ExUnit.Case
  doctest SensitiveData

  test "greets the world" do
    assert SensitiveData.hello() == :world
  end
end
