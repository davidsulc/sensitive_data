defmodule SensitiveData.DataType do
  alias SensitiveData.DataType.AtomType
  alias SensitiveData.DataType.BitstringType
  alias SensitiveData.DataType.MapType
  alias SensitiveData.DataType.NumberType

  def data_type(term) do
    cond do
      is_atom(term) ->
        AtomType.new!(term)

      is_map(term) ->
        MapType.new!(term)

      is_number(term) ->
        NumberType.new!(term)

      is_bitstring(term) ->
        BitstringType.new!(term)

      is_function(term) ->
        {:function, :erlang.fun_info(term)[:arity]}

      is_list(term) ->
        {:list, length(term)}

      is_pid(term) ->
        :pid

      is_port(term) ->
        :port

      is_reference(term) ->
        :reference

      is_tuple(term) ->
        {:tuple, tuple_size(term)}
    end
  end
end
