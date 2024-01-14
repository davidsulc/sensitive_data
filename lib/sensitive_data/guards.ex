defmodule SensitiveData.Guards do
  alias SensitiveData.DataType.AtomType
  alias SensitiveData.DataType.BitstringType
  alias SensitiveData.DataType.MapType
  alias SensitiveData.DataType.NumberType

  defguardp is_a(term, type) when is_tuple(term.data_type) and elem(term.data_type, 0) == type

  defguard is_sensitive(term) when is_struct(term) and term.__priv__.structure == SensitiveData

  defguard is_sensitive_list(term) when is_sensitive(term) and is_a(term, :list)

  defguard is_sensitive_tuple(term) when is_sensitive(term) and is_a(term, :tuple)

  defguard is_sensitive_function(term)
           when is_sensitive(term) and is_a(term, :function)

  defguard is_sensitive_function(term, arity)
           when is_sensitive_function(term) and elem(term.data_type, 1) == arity

  defguard is_sensitive_atom(term)
           when is_sensitive(term) and is_struct(term.data_type, AtomType)

  defguard is_sensitive_nil(term) when is_sensitive_atom(term) and term.data_type.is_nil == true

  defguard is_sensitive_boolean(term)
           when is_sensitive_atom(term) and term.data_type.is_boolean == true

  defguard is_sensitive_bitstring(term)
           when is_sensitive(term) and is_struct(term.data_type, BitstringType)

  defguard is_sensitive_binary(term)
           when is_sensitive_bitstring(term) and term.data_type.is_binary == true

  defguard is_sensitive_number(term)
           when is_sensitive(term) and is_struct(term.data_type, NumberType)

  defguard is_sensitive_float(term)
           when is_sensitive_number(term) and term.data_type.type == :float

  defguard is_sensitive_integer(term)
           when is_sensitive_number(term) and term.data_type.type == :integer

  defguard is_sensitive_map(term) when is_sensitive(term) and is_struct(term.data_type, MapType)

  defguard is_sensitive_exception(term)
           when is_sensitive_map(term) and term.data_type.is_exception == true

  defguard is_sensitive_exception(term, name)
           when is_sensitive_exception(term) and term.data_type.name == name
end
