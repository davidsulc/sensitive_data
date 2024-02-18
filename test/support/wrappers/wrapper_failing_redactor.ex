defmodule Wrappers.FailingRedactor do
  use SensitiveData.Wrapper, redactor: :redactor

  def redactor(_term), do: raise("redactor failed")
end
