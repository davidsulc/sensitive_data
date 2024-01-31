defmodule SensitiveData.WrapperTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import ExUnitProperties

  import StreamData

  # wrapper intsances used for testing
  alias Wrappers.{SensiData, SensiDataCust}

  doctest SensitiveData.Wrapper

  test "wrap/unwrap yields original value" do
    check all(
            term <- term(),
            wrapper_impl <- member_of([SensiData, SensiDataCust]),
            wrap_opts <- wrap_opts()
          ) do
      capture_log(fn ->
        wrapped = apply(wrapper_impl, :wrap, [term, wrap_opts])
        unwrapped = apply(wrapper_impl, :unwrap, [wrapped])

        assert unwrapped == term
      end)
    end
  end

  test "wrap/2" do
    check all(term <- term(), wrap_opts <- wrap_opts()) do
      capture_log(fn ->
        wrapped = SensiData.wrap(term, wrap_opts)

        # SensiData doesn't allow instance labels or redactors
        assert is_nil(wrapped.label)
        assert wrapped.redacted == SensitiveData.Redacted
      end)

      wrapped = SensiDataCust.wrap(term, wrap_opts)

      redactor = get_redactor(wrap_opts, wrapped)

      assert Keyword.get(wrap_opts, :label) == wrapped.label
      assert redactor.(term) == wrapped.redacted
    end
  end

  test "map/3" do
    check all(
            term <- term(),
            my_wrap_opts <- wrap_opts(),
            map_result <- term(),
            map_opts <- wrap_opts()
          ) do
      capture_log(fn ->
        wrapped = SensiData.wrap(term, my_wrap_opts)

        # check that label and redactor are ignored
        mapped = SensiData.map(wrapped, fn _ -> map_result end, map_opts)
        assert is_nil(mapped.label)
        assert mapped.redacted == SensitiveData.Redacted
        unwrapped = SensiData.unwrap(mapped)
        assert unwrapped == map_result
      end)

      wrapped = SensiDataCust.wrap(term, my_wrap_opts)

      expected_label = Keyword.get(map_opts, :label, wrapped.label)

      redactor = get_redactor(map_opts, wrapped)

      # check that label and redactor are updated and applied if given as opts,
      # otherwise the existing label and redactor are kept
      mapped = SensiDataCust.map(wrapped, fn _ -> map_result end, map_opts)
      assert expected_label == mapped.label
      assert redactor.(map_result) == mapped.redacted
      unwrapped = SensiDataCust.unwrap(mapped)
      assert unwrapped == map_result
    end
  end

  test "exec/3"

  test "to_redacted/1" do
    check all(data <- term(), redacted <- term()) do
      assert SensitiveData.Redacted == SensiData.wrap(data) |> SensiData.to_redacted()

      capture_log(fn ->
        assert SensitiveData.Redacted ==
                 SensiData.wrap(data, redactor: fn _ -> redacted end) |> SensiData.to_redacted()
      end)

      assert redacted ==
               SensiDataCust.wrap(data, redactor: fn _ -> redacted end)
               |> SensiDataCust.to_redacted()
    end
  end

  defp get_redactor(opts, %{} = wrapped) do
    Keyword.get(
      opts,
      :redactor,
      wrapped.__priv__.redactor || fn _ -> SensitiveData.Redacted end
    )
  end

  defp wrap_opts(),
    do:
      list_of(
        one_of([
          bind(term(), &constant({:label, &1})),
          bind(term(), fn term -> constant({:redactor, fn _ -> term end}) end)
        ])
      )
end
