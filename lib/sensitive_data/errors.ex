defmodule SensitiveData.InvalidIntoOptionError do
  @moduledoc false
  defexception message: "provided `:into` opts did not result in a valid wrapper"
end
