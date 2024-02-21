defmodule Wrappers.Redactor do
  def my_redactor(_term), do: "external redaction"
end

defmodule Wrappers.ExternalRedactor do
  use SensitiveData.Wrapper, redactor: {Wrappers.Redactor, :my_redactor}
end
