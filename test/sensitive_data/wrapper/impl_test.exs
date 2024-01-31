defmodule SensitiveData.Wrapper.ImplTest do
  use ExUnit.Case, async: true

  doctest SensitiveData.Wrapper

  # the functions in the Wrapper.Impl module are called
  # by wrapper implementation, so all functions are
  # tested by SensitiveData.WrapperTest
end
