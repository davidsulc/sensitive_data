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
  @callback to_redacted(wrapper :: t()) :: term()

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

  defmacro __using__(macro_opts) do
    allowed_macro_opts = [:default_label, :default_redactor]

    quote bind_quoted: [
            allowed_macro_opts: allowed_macro_opts,
            macro_opts: macro_opts
          ] do
      @typedoc ~s"""
      An instance of this wrapper.
      """
      @opaque t :: %__MODULE__{}

      @derive {Inspect, only: [:label, :redacted], optional: [:label, :redacted]}
      defstruct [:redacted, :label, :__priv__]

      # TODO compile flag to allow/forbid per-instance redactors

      @public_fields [:label, :redactor]

      @default_opts macro_opts
                    |> Keyword.take(allowed_macro_opts)
                    |> Keyword.new(fn {k, v} ->
                      case k do
                        :default_label -> {:label, v}
                        :default_redactor -> {:redactor, v}
                        _ -> {k, v}
                      end
                    end)

      @doc """
      Wraps the sensitive `term` to prevent unwanted data leaks.

      See `c:SensitiveData.Wrapper.wrap/2`.
      """
      @spec wrap(term, list) :: t()
      def wrap(term, opts \\ []) do
        SensitiveData.Wrapper.Impl.wrap(term,
          into: {__MODULE__, Keyword.merge(@default_opts, opts)}
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

      See `redactor/1`.
      """
      @spec to_redacted(t()) :: term()
      def to_redacted(%__MODULE__{} = wrapper),
        do: SensitiveData.Wrapper.Impl.to_redacted(wrapper)

      # There is no example provided here, as this is overridable.
      # If this function gets overridden but no `@doc` is provided, the content
      # here is used: having an incorrect example copied over would be
      # confusing.
      @doc """
      Returns a redacted equivalent of the provided sensitive `term`.

      See `to_redacted/1`.
      """
      @spec redactor(term()) :: term()
      def redactor(term), do: SensitiveData.Redacted

      defoverridable redactor: 1
    end
  end
end
