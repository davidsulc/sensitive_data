defmodule Wrappers.SensiDataCust do
  use SensitiveData.Wrapper, allow_instance_label: true, allow_instance_redactor: true

  def redactor(term), do: "#{inspect(term)}, but redacted"
end
