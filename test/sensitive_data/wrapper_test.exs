defmodule SensitiveData.WrapperTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import ExUnitProperties

  import StreamData

  require SensitiveData.Guards

  # wrapper instances used for testing
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

  test "from/exec work in tandem" do
    check all(
            term <- term(),
            wrapper_impl <- member_of([SensiData, SensiDataCust]),
            wrap_opts <- wrap_opts()
          ) do
      capture_log(fn ->
        wrapped = apply(wrapper_impl, :from, [fn -> term end, wrap_opts])
        unwrapped = apply(wrapper_impl, :exec, [wrapped, & &1])

        assert unwrapped == term
      end)
    end
  end

  test "from/exec are equivalent to wrap/unwrap" do
    check all(
            term <- term(),
            wrapper_impl <- member_of([SensiData, SensiDataCust]),
            wrap_opts <- wrap_opts()
          ) do
      capture_log(fn ->
        wrapped = apply(wrapper_impl, :wrap, [term, wrap_opts])
        unwrapped_by_exec = apply(wrapper_impl, :exec, [wrapped, & &1])

        wrapped_by_from = apply(wrapper_impl, :from, [fn -> term end, wrap_opts])
        unwrapped = apply(wrapper_impl, :unwrap, [wrapped_by_from])

        assert unwrapped_by_exec == term
        assert unwrapped == term
      end)
    end
  end

  test "wrap/2" do
    check all(term <- term(), wrap_opts <- wrap_opts()) do
      capture_log(fn ->
        wrapped = SensiData.wrap(term, wrap_opts)

        # SensiData doesn't allow instance labels
        assert is_nil(wrapped.label)
        assert is_nil(wrapped.redacted)
      end)

      wrapped = SensiDataCust.wrap(term, wrap_opts)

      assert Keyword.get(wrap_opts, :label) == wrapped.label
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
        assert is_nil(mapped.redacted)
        unwrapped = SensiData.unwrap(mapped)
        assert unwrapped == map_result
      end)

      wrapped = SensiDataCust.wrap(term, my_wrap_opts)

      expected_label = Keyword.get(map_opts, :label, wrapped.label)

      # check that label and redactor are updated and applied if given as opts,
      # otherwise the existing label and redactor are kept
      mapped = SensiDataCust.map(wrapped, fn _ -> map_result end, map_opts)
      assert expected_label == mapped.label
      unwrapped = SensiDataCust.unwrap(mapped)
      assert unwrapped == map_result
    end
  end

  test "exec/3" do
    check all(
            term <- term(),
            my_wrap_opts <- wrap_opts(),
            exec_result <- term(),
            into_opts <- wrap_opts()
          ) do
      wrapped = SensiDataCust.wrap(term, my_wrap_opts)

      capture_log(fn ->
        # check that label and redactor are ignored
        result =
          SensiDataCust.exec(wrapped, fn _ -> exec_result end, into: {SensiData, into_opts})

        assert is_nil(result.label)
        assert is_nil(result.redacted)
        assert SensiData.unwrap(result) == exec_result
      end)

      log =
        capture_log(fn ->
          wrapped = SensiData.wrap(term)

          # check that label and redactor are applied
          result =
            SensiData.exec(wrapped, fn _ -> exec_result end, into: {SensiDataCust, into_opts})

          assert result.label == Keyword.get(into_opts, :label)
          assert SensiDataCust.unwrap(result) == exec_result
        end)

      assert log == ""
    end
  end

  test "module functions only accept instances from the same module" do
    # we'll be executing SensiData functions, but with a SensiDataCust instance
    wrapper_mod = SensiData
    wrong_wrapper_type = SensiDataCust.wrap(:ok)

    functions_to_test = [
      exec: [fn _ -> :ok end],
      map: [fn _ -> :ok end],
      to_redacted: [],
      unwrap: []
    ]

    for [fun, args] <- functions_to_test do
      assert_raise FunctionClauseError, fn ->
        apply(wrapper_mod, fun, [wrong_wrapper_type | args])
      end
    end

    exported_functions =
      wrapper_mod.__info__(:functions)
      |> Keyword.keys()
      |> Enum.uniq()
      # reject private functions such as `__struct__`
      |> Enum.reject(&(&1 |> Atom.to_string() |> String.starts_with?("__")))

    # these are functions that don't expect a module struct instance
    # (and therefore aren't relevant to this test)
    ignored_functions = [
      :filter_wrap_opts,
      :from,
      :redactor,
      :wrap
    ]

    # `--` is right associative
    remaining = (exported_functions -- ignored_functions) -- Keyword.keys(functions_to_test)

    # if this fails, add the functions to either the `functions_to_test` or the `ignored_functions`
    assert [] == remaining, "some functions are neither tested nor ignored: #{inspect(remaining)}"
  end

  defp wrap_opts() do
    bind(term(), fn label ->
      one_of([constant([]), constant(label: label)])
    end)
  end
end
