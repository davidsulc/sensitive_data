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

  test "prune_args_from_stacktrace" do
    # we only care about the last call (and drop the file info from the tuple)
    show_last = fn stacktrace -> stacktrace |> hd() |> Tuple.delete_at(3) end

    stacktrace =
      try do
        Map.get("SOME SECRET", :some_key)
      rescue
        _ -> __STACKTRACE__
      end

    assert {Map, :get, ["SOME SECRET", :some_key, nil]} = show_last.(stacktrace)

    assert {Map, :get, 3} =
             stacktrace
             |> prune_args_from_stacktrace()
             |> show_last.()
  end
end
