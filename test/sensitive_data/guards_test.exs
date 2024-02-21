defmodule SensitiveData.GuardsTest do
  use ExUnit.Case, async: true
  import ExUnitProperties

  import Exceptions
  import StreamData
  import SensitiveData.Guards

  alias Wrappers.SensiData

  test "is_sensitive/1 guard" do
    check all(data <- one_of(Keyword.values(generators()))) do
      case {SensiData.wrap(data), data} do
        {wrapped, unwrapped} when is_sensitive(wrapped) and not is_sensitive(unwrapped) ->
          :ok

        _ ->
          flunk("guard failed to work")
      end
    end
  end

  test "is_sensitive/2 guard" do
    check all(data <- one_of(Keyword.values(generators()))) do
      case SensiData.wrap(data) do
        wrapped
        when is_sensitive(wrapped, SensiData) and not is_sensitive(wrapped, SensiDataCust) ->
          :ok

        _ ->
          flunk("guard failed to work")
      end
    end
  end

  for {guard_name, generators} <- [
        {:is_sensitive_atom, [:atom, :boolean, nil]},
        {:is_sensitive_bitstring, [:bitstring, :string]},
        {:is_sensitive_boolean, [:boolean]},
        {:is_sensitive_exception, [:exception]},
        {:is_sensitive_function, [:function]},
        {:is_sensitive_float, [:float]},
        {:is_sensitive_integer, [:integer]},
        {:is_sensitive_list, [:list]},
        {:is_sensitive_map, [:map, :exception]},
        {:is_sensitive_nil, [nil]},
        {:is_sensitive_number, [:integer, :float]},
        {:is_sensitive_tuple, [:tuple]}
      ] do
    test "#{Atom.to_string(guard_name)}/1 guard" do
      generator_names = unquote(generators)

      check all(
              data_match <- generators(generator_names),
              data_no_match <- generators(except: generator_names)
            ) do
        case {SensiData.wrap(data_match), SensiData.wrap(data_no_match)} do
          {match, no_match}
          when unquote({guard_name, [], [{:match, [], nil}]}) and
                 not unquote({guard_name, [], [{:no_match, [], nil}]}) ->
            :ok

          _ ->
            flunk("guard failed to work")
        end
      end
    end
  end

  # This test isn't generated like the others, because the :bitstring generator
  # may generate a valid string (which would fail the `refute` expression).
  test "is_sensitive_binary/1 guard" do
    check all(
            data_match <- generators([:string]),
            data_no_match <-
              bind_filter(generators(except: [:string, :bitstring]), fn
                term when is_binary(term) -> :skip
                term -> {:cont, constant(term)}
              end)
          ) do
      case {SensiData.wrap(data_match), SensiData.wrap(data_no_match)} do
        {match, no_match}
        when is_sensitive_binary(match) and not is_sensitive_binary(no_match) ->
          :ok

        _ ->
          flunk("guard failed to work")
      end
    end
  end

  test "is_sensitive_function/2 guard" do
    for arity <- 0..9 do
      check all(
              fun <- function(arity),
              not_fun <-
                generators(except: [:function])
            ) do
        case {SensiData.wrap(fun), SensiData.wrap(not_fun)} do
          {wrapped_fun, wrapped_other}
          when is_sensitive_function(wrapped_fun, arity) and
                 not is_sensitive_function(wrapped_other, arity) ->
            :ok

          _ ->
            flunk("guard failed to work")
        end

        for not_arity <- 0..9, not_arity != arity do
          case {SensiData.wrap(fun), SensiData.wrap(not_fun)} do
            {wrapped_fun, wrapped_other}
            when not is_sensitive_function(wrapped_fun, not_arity) and
                   not is_sensitive_function(wrapped_other, not_arity) ->
              :ok

            _ ->
              flunk("guard failed to work")
          end
        end
      end
    end
  end

  test "is_sensitive_exception/2 guard" do
    check all(
            {exception, not_exception_name} <-
              bind(exception(), fn e ->
                bind_filter(member_of(exception_names()), fn other_name ->
                  %exception_name{} = e

                  case other_name == exception_name do
                    true -> :skip
                    false -> {:cont, constant({e, other_name})}
                  end
                end)
              end)
          ) do
      wrapped = SensiData.wrap(exception)
      %exception_name{} = exception

      case {wrapped, exception_name, not_exception_name} do
        {wrapped, exception_name, not_exception_name}
        when is_sensitive_exception(wrapped, exception_name) and
               not is_sensitive_exception(wrapped, not_exception_name) ->
          :ok

        _ ->
          flunk("guard failed to work")
      end
    end
  end

  defp generators([{:except, to_exclude}]) do
    generators()
    |> Keyword.drop(to_exclude)
    |> Keyword.values()
    |> one_of()
  end

  defp generators(to_take) do
    filtered_generators = generators() |> Keyword.take(to_take)

    case filtered_generators do
      # make sure we're passing valid `to_take` options that will result in
      # a non-empty list of generators
      [_ | _] ->
        filtered_generators
        |> Keyword.values()
        |> one_of()
    end
  end

  defp generators() do
    [
      atom: one_of([atom(:alphanumeric), atom(:alias)]),
      bitstring: bitstring(),
      boolean: boolean(),
      exception: exception(),
      float: float(),
      function: function(),
      integer: integer(),
      map: map_of(term(), term()),
      nil: constant(nil),
      list: list_of(term()),
      string: string(:utf8),
      tuple: bind(list_of(term()), fn list -> constant(List.to_tuple(list)) end)
    ]
  end

  defp function(arity \\ :any) do
    arity_generator =
      case arity do
        :any -> integer(0..9)
        n when is_integer(n) and n >= 0 and n < 10 -> constant(n)
      end

    bind({arity_generator, term()}, fn {function_arity, result} ->
      funs_by_arity = %{
        0 => fn -> result end,
        1 => fn _ -> result end,
        2 => fn _, _ -> result end,
        3 => fn _, _, _ -> result end,
        4 => fn _, _, _, _ -> result end,
        5 => fn _, _, _, _, _ -> result end,
        6 => fn _, _, _, _, _, _ -> result end,
        7 => fn _, _, _, _, _, _, _ -> result end,
        8 => fn _, _, _, _, _, _, _, _ -> result end,
        9 => fn _, _, _, _, _, _, _, _, _ -> result end
      }

      funs_by_arity
      |> Map.fetch!(function_arity)
      |> constant()
    end)
  end
end
