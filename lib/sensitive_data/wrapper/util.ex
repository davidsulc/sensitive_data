defmodule SensitiveData.Wrapper.Util do
  @moduledoc """
  Utility functions for sensitive data wrappers.
  """

  import SensitiveData.Guards,
    only: [is_sensitive_list: 1, is_sensitive_map: 1, is_sensitive_tuple: 1]

  alias SensitiveData.Wrapper

  @doc """
  Returns the length of the list wrapped within `term`.
  """
  @spec sensitive_length(Wrapper.t()) :: non_neg_integer()
  def sensitive_length(term) when is_sensitive_list(term), do: elem(term.__priv__.data_type, 1)

  @doc """
  Returns the size of the map wrapped within `term`.

  The size of a map is the number of key-value pairs that the map contains.

  This operation happens in constant time.
  """
  @spec sensitive_map_size(Wrapper.t()) :: non_neg_integer()
  def sensitive_map_size(term) when is_sensitive_map(term), do: term.__priv__.data_type.size

  @doc """
  Returns the size of a tuple wrapped within `term`.

  This operation happens in constant time.
  """
  @spec sensitive_tuple_size(Wrapper.t()) :: non_neg_integer()
  def sensitive_tuple_size(term) when is_sensitive_tuple(term),
    do: elem(term.__priv__.data_type, 1)
end
