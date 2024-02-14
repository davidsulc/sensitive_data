defmodule Wrappers.SensiDataCust do
  use SensitiveData.Wrapper,
    allow_label: true,
    redactor: :custom_redactor,
    unwrap: true,
    wrap: true

  # TODO document default redactor (and fallback to SensitiveData.Redacted)
  def custom_redactor(term), do: "#{inspect(term)}, but redacted"
end
