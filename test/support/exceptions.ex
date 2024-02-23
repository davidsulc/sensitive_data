defmodule Support.Exceptions do
  import StreamData

  @exception_names_with_message [
    ArithmeticError,
    ArgumentError,
    Enum.EmptyError,
    Enum.OutOfBoundsError,
    OptionParser.ParseError,
    Regex.CompileError,
    RuntimeError
  ]

  @exception_names_with_term [
    BadFunctionError,
    BadFunctionError,
    BadMapError,
    BadStructError,
    CaseClauseError,
    MatchError,
    TryClauseError,
    WithClauseError
  ]

  @exception_names_other [
    BadArityError,
    Code.LoadError,
    KeyError
  ]

  @exception_names @exception_names_with_message ++
                     @exception_names_with_term ++ @exception_names_other

  def exception_names_with_message(), do: @exception_names_with_message

  def exception_names_with_term(), do: @exception_names_with_term

  def exception_names_other(), do: @exception_names_other

  def exception_names(), do: @exception_names

  def exception() do
    one_of([
      exception_with_message(),
      exception_with_term(),
      exception_with_multiple_args()
    ])
  end

  def exception_with_message() do
    bind(member_of(exception_names_with_message()), fn e ->
      bind(string(:alphanumeric, min_length: 1), fn arg ->
        constant(apply(e, :exception, [arg]))
      end)
    end)
  end

  def exception_with_term() do
    bind(member_of(exception_names_with_term()), fn e ->
      bind(term(), fn arg ->
        constant(apply(e, :exception, [[term: arg]]))
      end)
    end)
  end

  def exception_with_multiple_args() do
    one_of([exception_bad_arity_error(), exception_key_error(), exception_code_load_error()])
  end

  def exception_bad_arity_error() do
    bind({atom(:alphanumeric), list_of(term())}, fn {function, args} ->
      constant(BadArityError.exception(function: function, args: args))
    end)
  end

  def exception_key_error() do
    bind({atom(:alphanumeric), term(), string(:printable)}, fn {key, term, message} ->
      constant(KeyError.exception(key: key, term: term, message: message))
    end)
  end

  def exception_code_load_error() do
    bind({atom(:alphanumeric), string(:printable)}, fn {file, reason} ->
      constant(Code.LoadError.exception(file: file, reason: reason))
    end)
  end
end
