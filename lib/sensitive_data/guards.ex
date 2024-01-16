defmodule SensitiveData.Guards do
  @moduledoc """
  Guards for sensitive data wrappers.

  This module includes guards that work with `t:SensitiveData.Wrapper.t/0` wrappers. For example:

      import SensitiveData.Guards, only: [is_sensitive_binary: 1]

      def send_request(key) when is_sensitive_binary(key) do
        ...
      end

  For more information on guards, refer to Elixir's
  [Patterns and guards](https://hexdocs.pm/elixir/patterns-and-guards.html) page.
  """
  alias SensitiveData.DataType.AtomType
  alias SensitiveData.DataType.BitstringType
  alias SensitiveData.DataType.MapType
  alias SensitiveData.DataType.NumberType

  defguardp is_a(term, type)
            when is_tuple(term.__priv__.data_type) and elem(term.__priv__.data_type, 0) == type

  @doc """
  Returns `true` if `term` is a `t:SensitiveData.Wrapper.t/0`;
  otherwise returns false.

  Allowed in guard tests.
  """
  defguard is_sensitive(term) when is_struct(term) and term.__priv__.structure == SensitiveData

  defguard is_sensitive_list(term) when is_sensitive(term) and is_a(term, :list)

  defguard is_sensitive_tuple(term) when is_sensitive(term) and is_a(term, :tuple)

  defguard is_sensitive_function(term)
           when is_sensitive(term) and is_a(term, :function)

  defguard is_sensitive_function(term, arity)
           when is_sensitive_function(term) and elem(term.__priv__.data_type, 1) == arity

  defguard is_sensitive_atom(term)
           when is_sensitive(term) and is_struct(term.__priv__.data_type, AtomType)

  defguard is_sensitive_nil(term)
           when is_sensitive_atom(term) and term.__priv__.data_type.is_nil == true

  defguard is_sensitive_boolean(term)
           when is_sensitive_atom(term) and term.__priv__.data_type.is_boolean == true

  defguard is_sensitive_bitstring(term)
           when is_sensitive(term) and is_struct(term.__priv__.data_type, BitstringType)

  defguard is_sensitive_binary(term)
           when is_sensitive_bitstring(term) and term.__priv__.data_type.is_binary == true

  defguard is_sensitive_number(term)
           when is_sensitive(term) and is_struct(term.__priv__.data_type, NumberType)

  defguard is_sensitive_float(term)
           when is_sensitive_number(term) and term.__priv__.data_type.type == :float

  defguard is_sensitive_integer(term)
           when is_sensitive_number(term) and term.__priv__.data_type.type == :integer

  @doc """
  Returns `true` if `term` is a `t:SensitiveData.Wrapper.t/0` containing a map;
  otherwise returns false.

  Allowed in guard tests.
  """
  defguard is_sensitive_map(term)
           when is_sensitive(term) and is_struct(term.__priv__.data_type, MapType)

  @doc """
  Returns `true` if `term` is a `t:SensitiveData.Wrapper.t/0` containing an
  `t:Exception.t/0`; otherwise returns false.

  Allowed in guard tests.
  """
  defguard is_sensitive_exception(term)
           when is_sensitive_map(term) and term.__priv__.data_type.is_exception == true

  defguard is_sensitive_exception(term, name)
           when is_sensitive_exception(term) and term.__priv__.data_type.name == name
end
