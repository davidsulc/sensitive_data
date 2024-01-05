defmodule SensitiveData do
  @moduledoc """
  Documentation for `SensitiveData`.
  """

  @doc """
  Hello world.

  ## Examples

      iex> SensitiveData.hello()
      :world

  """
  def hello do
    :world
  end

  @doc """
  Reads a line from stdin, without echoing the input back to the console.

  ## Examples

  To display "Enter your password: " as a prompt and await user input:

      SensitiveData.get_sensitive("Enter your password: ")
  """
  @spec gets_sensitive(String.t()) :: String.t()
  defdelegate gets_sensitive(prompt \\ ""), to: SensitiveData.IO
end
