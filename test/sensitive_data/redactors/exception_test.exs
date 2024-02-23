defmodule SensitiveData.Redactors.ExceptionTest do
  use ExUnit.Case, async: true

  doctest SensitiveData.Redactors.Exception

  import SensitiveData.Redactors.Exception

  alias SensitiveData.RedactedException

  test "drop/1" do
    exception = Support.Exceptions.exception() |> Enum.take(1) |> hd()
    assert is_exception(drop(exception), RedactedException)
  end
end
