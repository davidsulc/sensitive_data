defmodule SensitiveData.Guards.Util do
  import SensitiveData.Guards,
    only: [is_sensitive_list: 1, is_sensitive_map: 1, is_sensitive_tuple: 1]

  def sensitive_length(term) when is_sensitive_list(term), do: elem(term.data_type, 1)

  def sensitive_map_size(term) when is_sensitive_map(term), do: term.data_type.size

  def sensitive_tuple_size(term) when is_sensitive_tuple(term), do: elem(term.data_type, 1)
end
