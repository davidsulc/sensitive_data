defmodule SensitiveDataTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import ExUnitProperties

  import StreamData
  import SensitiveData

  alias Wrappers.{SensiData, SensiDataCust}

  doctest SensitiveData

  defp capture_exception_io(fun) do
    try do
      fun.()
    rescue
      e -> {inspect(e), inspect(__STACKTRACE__)}
    end
  end

  test "exec/1" do
    secret = "SECRET"
    test_action = fn -> Map.get(secret, :bad_key) end

    # secrets leak normally
    {error_message, stacktrace} = capture_exception_io(test_action)

    assert String.contains?(error_message, secret)

    assert String.contains?(stacktrace, secret)

    # secrets don't leak from within `exec`
    {error_message, stacktrace} =
      capture_exception_io(fn -> exec(test_action) end)

    refute String.contains?(error_message, secret)

    refute String.contains?(stacktrace, secret)

    # redaction can be customized
    custom_redaction_exception = "CUSTOM_REDACTION_EXCEPTION"
    custom_redaction_stacktrace = "CUSTOM_REDACTION_STACKTRACE"

    {error_message, stacktrace} =
      capture_exception_io(fn ->
        exec(test_action,
          exception_redaction: fn _val, _term -> custom_redaction_exception end,
          stacktrace_redaction: fn _args -> custom_redaction_stacktrace end
        )
      end)

    assert String.contains?(error_message, custom_redaction_exception)
    assert String.contains?(stacktrace, custom_redaction_stacktrace)

    refute String.contains?(error_message, secret)
    refute String.contains?(stacktrace, secret)
  end

  test "exec into" do
    check all(term <- term(), label <- term(), redacted <- string(:printable)) do
      wrapped = exec(fn -> term end, into: SensiData)

      assert SensiData.unwrap(wrapped) == term
      assert is_nil(wrapped.label)
      assert SensiData.to_redacted(wrapped) == SensitiveData.Redacted

      wrapped_with_opts =
        exec(fn -> term end, into: {SensiDataCust, label: label, redactor: fn _ -> redacted end})

      assert SensiDataCust.unwrap(wrapped_with_opts) == term
      assert wrapped_with_opts.label == label
      assert SensiDataCust.to_redacted(wrapped_with_opts) == redacted

      # opts get dropped if not allowed in call to `use`
      capture_log(fn ->
        wrapped_with_opts =
          exec(fn -> term end, into: {SensiData, label: label, redactor: fn _ -> redacted end})

        assert SensiData.unwrap(wrapped_with_opts) == term
        assert is_nil(wrapped_with_opts.label)
        assert SensiData.to_redacted(wrapped_with_opts) == SensitiveData.Redacted
      end)
    end
  end

  test "exec into with invalid :into target" do
    for into_opts <- [List, {List, [:foo, :bar]}, "foo"] do
      assert_raise(ArgumentError, "provided `:into` opts did not result in a valid wrapper", fn ->
        exec(fn -> :foo end, into: into_opts)
      end)
    end
  end
end
