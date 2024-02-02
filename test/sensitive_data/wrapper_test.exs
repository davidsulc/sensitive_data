defmodule SensitiveData.WrapperTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureLog, only: [capture_log: 1]
  import ExUnitProperties

  import StreamData

  require SensitiveData.Guards

  alias SensitiveData.Guards
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
        assert result.redacted == SensitiveData.Redacted
        assert SensiData.unwrap(result) == exec_result
      end)

      log =
        capture_log(fn ->
          wrapped = SensiData.wrap(term)

          # check that label and redactor are applied
          result =
            SensiData.exec(wrapped, fn _ -> exec_result end, into: {SensiDataCust, into_opts})

          case get_redactor(into_opts, SensiDataCust) do
            nil -> assert is_nil(result.redacted)
            redactor -> assert redactor.(exec_result) == result.redacted
          end

          assert result.label == Keyword.get(into_opts, :label)
          assert SensiDataCust.unwrap(result) == exec_result
        end)

      assert log == ""
    end
  end

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
      :redactor,
      :wrap
    ]

    # `--` is right associative
    remaining = (exported_functions -- ignored_functions) -- Keyword.keys(functions_to_test)

    # if this fails, add the functions to either the `functions_to_test` or the `ignored_functions`
    assert [] == remaining, "some functions are neither tested nor ignored: #{inspect(remaining)}"
  end

  defp get_redactor(opts, wrapper_mod) when is_atom(wrapper_mod) do
    case Keyword.get(opts, :redactor) do
      nil ->
        case function_exported?(wrapper_mod, :redactor, 1) do
          true -> &wrapper_mod.redactor/1
          false -> nil
        end

      redactor ->
        redactor
    end
  end

  defp get_redactor(opts, wrapper) when Guards.is_sensitive(wrapper),
    do: get_redactor_or_default(opts, wrapper.__priv__.redactor)

  defp get_redactor_or_default(opts, default_redacted),
    do: Keyword.get(opts, :redactor, default_redacted || fn _ -> SensitiveData.Redacted end)

  defp wrap_opts() do
    bind(term(), fn label ->
      bind(term(), fn redaction_result ->
        bind(integer(0..2), fn count ->
          [label: label, redactor: fn _ -> redaction_result end]
          |> Enum.shuffle()
          |> Enum.take(count)
          |> constant()
        end)
      end)
    end)
  end
end
