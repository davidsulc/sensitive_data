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

  defdelegate gets_sensitive(prompt \\ ""), to: SensitiveData.IO
end
