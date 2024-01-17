defmodule SensitiveData.Wrapper do
  @moduledoc """
  Defines a wrapper for sensitive data.

  ## Labeling and Redacting

  TODO
  """

  alias SensitiveData.Redaction

  @typedoc """
  A wrapper containing sensitive data.

  The wrapper structure should be considered opaque, aside from the `label` and
  `redacted` fields (see
  [labeling and redacting section](#module-labeling-and-redacting)). You may
  read and match on those fields, but accessing any other fields or directly
  modifying any field is not advised.

  Limited information regarding the contained sensitive data can be obtained
  via the guards in `SensitiveData.Guards` and the functions in
  `SensitiveData.Wrapper.Util`.
  """
  @type t() :: %{
          :__struct__ => atom(),
          :label => term(),
          :redacted => term(),
          optional(atom()) => term()
        }
  @type spec :: wrapper_module() | {wrapper_module(), wrap_opts()}
  @typedoc """
  A module implementing the `c:wrap/2` callback.
  """
  @type wrapper_module :: atom()
  @typedoc """
  Wrapping options.

  See `c:SensitiveData.Wrapper.wrap/2`.
  """
  @type wrap_opts :: [label: term(), redactor: Redaction.redactor()]

  @doc """
  Wraps the sensitive `term` to prevent unwanted data leaks.

  The sensitive term may later be retrieved via `unwrap/1`.

  ## Options

  - `:label` - a label displayed when the wrapper is inspected
  - `:redactor` - a redaction function returning the redacted equivalent of the
    given term

  ## Examples

      MySensitiveData.wrap("foo")
      # #MySensitiveData<...>

      MySensitiveData.wrap("123451234512345", label: :credit_card_user_bob)
      # #MySensitiveData<label: :credit_card_user_bob, ...>

      MySensitiveData.wrap("123451234512345", label: :credit_card_user_bob,
        redactor: fn credit_card_number ->
          digits = String.split(credit_card_number, "", trim: true)
          {to_redact, last} = Enum.split(digits, length(digits) - 4)
          IO.iodata_to_binary([String.duplicate("*", length(to_redact)), last])
        end)
      # #MySensitiveData<redacted: "***********2345",
          label: :credit_card_user_bob, ...>
  """
  @callback wrap(term(), wrap_opts()) :: t()

  @doc """
  Returns the sensitive term within `wrapper`.
  """
  @callback unwrap(wrapper :: t()) :: term()

  @doc """
  Returns the redacted equivalent of the sensitive term within `wrapper`.
  """
  # TODO document redaction order (redactor from wrap option, default redactor,
  # fallback to Redacted)
  @callback to_redacted(wrapper :: t()) :: term()

  @doc """
  Returns a redacted equivalent of the provided sensitive `term`.
  """
  @callback redactor(term()) :: term()

  @doc """
  Returns a label to describe the given sensitive `term`.

  The label will be maintained as a field within the wrapper (see
  [labeling and redacting section](#module-labeling-and-redacting))
  and can be used to assist in determining what the wrapped sensitive value
  was then the wrapper is inspected (manually when debugging, via Observer,
  dumped in crashes, and so on).

  ## Example

      defmodule DatabaseCredentials do
        use SensitiveData

        def labeler(%{username: _, password: _}), do: :username_and_password
        def labeler(%URI{}), do: :connection_uri
      end

      DatabaseCredentials.wrap(%{username: "foo", password: "bar"})
      # #DatabaseCredentials<label: :credit_card_user_bob, ...>
  """
  @callback labeler(term()) :: term()

  @optional_callbacks labeler: 1, redactor: 1

  @doc false
  @spec spec(spec()) :: {:ok, {atom(), wrap_opts()}} | {:error, Exception.t()}
  # TODO verify mod has wrap function, and that the result is_sensitive
  def spec({mod, opts}) when is_atom(mod) and is_list(opts), do: {:ok, {mod, opts}}
  # TODO FIXME handle error cases (nil, bad mod, etc.)
  def spec(mod) when is_atom(mod), do: spec({mod, []})

  @doc false
  @spec spec!(spec()) :: {atom(), Keyword.t()}
  def spec!(spec) do
    with {:ok, valid_spec} <- spec(spec) do
      valid_spec
    else
      {:error, e} -> raise e
    end
  end

  @doc false
  def from_spec!({mod, opts}, raw_data),
    do: SensitiveData.execute(fn -> apply(mod, :wrap, [raw_data | [opts]]) end)

  defmacro __using__(_) do
    quote do
      @typedoc ~s"""
      An instance of this wrapper.
      """
      @opaque t :: %__MODULE__{}

      @derive {Inspect, only: [:label, :redacted], optional: [:label, :redacted]}
      defstruct [:redacted, :label, :__priv__]

      # TODO compile flag to allow/forbid per-instance redactors

      @public_fields [:label, :redactor]

      @doc """
      Wraps the sensitive `term` to prevent unwanted data leaks.

      See `c:SensitiveData.Wrapper.wrap/2`.
      """
      @spec wrap(term, list) :: t()
      def wrap(term, opts \\ []) do
        SensitiveData.Wrapper.Impl.wrap(term,
          into: {__MODULE__, Keyword.take(opts, [:label, :redactor])}
        )
      end

      @doc """
      Returns the sensitive term within `wrapper`.

      See `c:SensitiveData.Wrapper.unwrap/1`.
      """
      @spec unwrap(t()) :: term()
      def unwrap(%__MODULE__{} = wrapper), do: SensitiveData.Wrapper.Impl.unwrap(wrapper)

      @doc """
      Returns the redacted equivalent of the sensitive term within `wrapper`.

      See `c:SensitiveData.Wrapper.to_redacted/1`.
      """
      @spec to_redacted(t()) :: term()
      def to_redacted(%__MODULE__{} = wrapper),
        do: SensitiveData.Wrapper.Impl.to_redacted(wrapper)
    end
  end
end
