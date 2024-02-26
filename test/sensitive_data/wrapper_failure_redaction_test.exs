defmodule SensitiveData.WrapperFailureRedactionTest do
  use ExUnit.Case, async: false

  alias Wrappers.FailureRedaction

  setup do
    %{wrapper: FailureRedaction.from(fn -> :foo end)}
  end

  test "custom failure redaction in wrapper", %{wrapper: wrapper} do
    try do
      FailureRedaction.from(fn -> raise "boom" end)
    rescue
      _ -> :ok
    end

    assert_received({:exception_redactor, %RuntimeError{message: "boom"}})
    assert_received({:stacktrace_redactor, _})

    try do
      FailureRedaction.map(wrapper, fn _ -> raise "boom" end)
    rescue
      _ -> :ok
    end

    assert_received({:exception_redactor, %RuntimeError{message: "boom"}})
    assert_received({:stacktrace_redactor, _})

    try do
      FailureRedaction.exec(wrapper, fn _ -> raise "boom" end)
    rescue
      _ -> :ok
    end

    assert_received({:exception_redactor, %RuntimeError{message: "boom"}})
    assert_received({:stacktrace_redactor, _})
  end
end
