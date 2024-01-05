defmodule SensitiveData do
  @moduledoc """
  Documentation for `SensitiveData`.
  """

  alias SensitiveData.IO
  alias SensitiveData.Redaction

  @doc """
  Executes the provided function, ensuring no data leaks in case of error.

  ## Examples

      iex> SensitiveData.execute(fn ->
      ...>   Map.get("SOME_PASSWORD", :foobar)
      ...> end)
      ** (BadMapError) expected a map, got: SensitiveData.Redacted
  """
  @spec execute((-> result)) :: result when result: term() | no_return()
  def execute(fun) when is_function(fun, 0) do
    try do
      fun.()
    rescue
      e ->
        reraise Redaction.prune_exception(e),
                Redaction.prune_args_from_stacktrace(__STACKTRACE__)
    end
  end

  @doc """
  Reads a line from stdin, without echoing the input back to the console.

  ## Examples

  To display "Enter your password: " as a prompt and await user input:

      SensitiveData.get_sensitive("Enter your password: ")
  """
  @spec gets_sensitive(String.t()) :: String.t()
  defdelegate gets_sensitive(prompt \\ ""), to: IO
end
