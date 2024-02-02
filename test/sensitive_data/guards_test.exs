defmodule SensitiveData.GuardsTest do
  use ExUnit.Case, async: true
  import ExUnitProperties

  import StreamData
  import SensitiveData.Guards

  alias Wrappers.SensiData

  @exception_names_with_message [
    ArithmeticError,
    ArgumentError,
    Enum.EmptyError,
    Enum.OutOfBoundsError,
    OptionParser.ParseError,
    Regex.CompileError,
    RuntimeError,
    SystemLimitError
  ]

  @exception_names_with_term [
    BadFunctionError,
    BadFunctionError,
    BadMapError,
    BadStructError,
    CaseClauseError,
    MatchError,
    TryClauseError,
    WithClauseError
  ]

  @exception_names_other [
    BadArityError,
    Code.LoadError,
    KeyError
  ]

  @exception_names @exception_names_with_message ++
                     @exception_names_with_term ++ @exception_names_other

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
              # TODO use separate clauses (and refactor other tests for same reason)
              {data_match, data_no_match} <-
                {generators(generator_names), generators(except: generator_names)}
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
            {data_match, data_no_match} <-
              {generators([:string]),
               bind_filter(generators(except: [:string, :bitstring]), fn
                 term when is_binary(term) -> :skip
                 term -> {:cont, constant(term)}
               end)}
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
      check all({fun, not_fun} <- {function(arity), generators(except: [:function])}) do
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
                bind_filter(member_of(@exception_names), fn other_name ->
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

  defp exception() do
    one_of([
      exception_with_message(),
      exception_with_term(),
      exception_with_multiple_args()
    ])
  end

  defp exception_with_message() do
    bind(member_of(exception_names_with_message()), fn e ->
      bind(string(:alphanumeric, min_length: 1), fn arg ->
        constant(apply(e, :exception, [arg]))
      end)
    end)
  end

  defp exception_with_term() do
    bind(member_of(exception_names_with_term()), fn e ->
      bind(term(), fn arg ->
        constant(apply(e, :exception, [[term: arg]]))
      end)
    end)
  end

  defp exception_with_multiple_args() do
    one_of([exception_bad_arity_error(), exception_key_error(), exception_code_load_error()])
  end

  defp exception_bad_arity_error() do
    bind({atom(:alphanumeric), list_of(term())}, fn {function, args} ->
      constant(BadArityError.exception(function: function, args: args))
    end)
  end

  defp exception_key_error() do
    bind({atom(:alphanumeric), term(), string(:printable)}, fn {key, term, message} ->
      constant(KeyError.exception(key: key, term: term, message: message))
    end)
  end

  defp exception_code_load_error() do
    bind({atom(:alphanumeric), string(:printable)}, fn {file, reason} ->
      constant(Code.LoadError.exception(file: file, reason: reason))
    end)
  end

  defp exception_names_with_message(), do: @exception_names_with_message

  defp exception_names_with_term(), do: @exception_names_with_term

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
