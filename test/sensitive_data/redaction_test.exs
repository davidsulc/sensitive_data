defmodule SensitiveData.RedactionTest do
  use ExUnit.Case
  doctest SensitiveData.Redaction

  import SensitiveData.Redaction

  test "prune_exception" do
    pruned_exception =
      try do
        Map.get("SOME SECRET", :some_key)
      rescue
        e -> prune_exception(e)
      end

    assert %BadMapError{term: SensitiveData.Redacted} = pruned_exception
  end
end
