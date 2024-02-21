defmodule SensitiveData.WrapperTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import ExUnitProperties

  import StreamData

  require SensitiveData.Guards

  # wrapper instances used for testing
  alias Wrappers.{ExternalRedactor, FailingRedactor, SensiData, SensiDataCust}

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

        # check that label is ignored
        mapped = SensiData.map(wrapped, fn _ -> map_result end, map_opts)
        assert is_nil(mapped.label)
        unwrapped = SensiData.unwrap(mapped)
        assert unwrapped == map_result
      end)

      wrapped = SensiDataCust.wrap(term, my_wrap_opts)

      expected_label = Keyword.get(map_opts, :label, wrapped.label)

      # check that label is updated and applied if given as opts,
      # otherwise the existing label is kept
      mapped = SensiDataCust.map(wrapped, fn _ -> map_result end, map_opts)
      assert expected_label == mapped.label
      unwrapped = SensiDataCust.unwrap(mapped)
      assert unwrapped == map_result
    end
  end

  @tag :wip
  test "exec/3" do
    check all(
            term <- term(),
            my_wrap_opts <- wrap_opts(),
            exec_result <- term(),
            into_opts <- wrap_opts()
          ) do
      wrapped = SensiDataCust.wrap(term, my_wrap_opts)

      capture_log(fn ->
        # check that label is ignored
        result =
          SensiDataCust.exec(wrapped, fn _ -> exec_result end, into: {SensiData, into_opts})

        assert is_nil(result.label)
        assert is_nil(result.redacted)
        assert SensiData.unwrap(result) == exec_result

        result_no_label =
          SensiDataCust.exec(wrapped, fn _ -> exec_result end, into: SensiData)

        assert result == result_no_label
      end)

      log =
        capture_log(fn ->
          wrapped = SensiData.wrap(term)

          # check that label is applied
          result =
            SensiData.exec(wrapped, fn _ -> exec_result end, into: {SensiDataCust, into_opts})

          assert result.label == Keyword.get(into_opts, :label)
          assert SensiDataCust.unwrap(result) == exec_result
        end)

      assert log == ""
    end
  end

  test "exec logs invalid and disallowed into opts" do
    log =
      capture_log(fn ->
        SensiDataCust.wrap(:foo)
        |> SensiDataCust.exec(fn _ -> :bar end, into: {SensiData, label: :label, foo: :bar})
      end)

    assert String.contains?(log, "dropping invalid wrapper options:\n\n  [:foo]")
    assert String.contains?(log, "dropping disallowed wrapper options:\n\n  [:label]")
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

  test "external redaction works" do
    data = ExternalRedactor.from(fn -> "foo" end)

    assert data.redacted == "external redaction"
  end

  test "redaction failure results in Redacted" do
    data = FailingRedactor.from(fn -> "foo" end)

    assert data.redacted == SensitiveData.Redacted
  end

  test "using disallowed label option gets logged" do
    for data_provider <- [
          fn -> SensiData.from(fn -> "foo" end, label: :test) end,
          fn -> SensiData.wrap("foo", label: :test) end,
          fn -> SensitiveData.exec(fn -> "foo" end, into: {SensiData, label: :test}) end,
          fn ->
            base_data = SensiDataCust.from(fn -> "foo" end)
            SensiDataCust.exec(base_data, fn _term -> "foo" end, into: {SensiData, label: :test})
          end
        ] do
      log =
        capture_log(fn ->
          data = data_provider.()

          assert data.label == nil
        end)

      assert String.contains?(
               log,
               "dropping disallowed wrapper options"
             )
    end
  end

  defp wrap_opts() do
    bind(term(), fn label ->
      one_of([constant([]), constant(label: label)])
    end)
  end
end
