defmodule Wrappers.SensiDataCust do
  use SensitiveData.Wrapper,
    allow_instance_label: true,
    allow_instance_redactor: true,
    allow_unwrap: true

  # TODO document default redactor (and fallback to SensitiveData.Redacted)
  def redactor(term), do: "#{inspect(term)}, but redacted"
end
