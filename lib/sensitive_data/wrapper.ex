defmodule SensitiveData.Wrapper do
  @moduledoc """
  Defines a wrapper for sensitive data.

  ## Labeling and Redacting

  TODO

  TODO: document can use label for matching

  TODO document __using__: allow_instance_label, etc.
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

  @typedoc """
  Execution options.

  See `c:SensitiveData.Wrapper.exec/3`.
  """
  @type exec_opts :: [into: spec()]

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
  Invokes the callback on the wrapped sensitive term and returns the wrapped result.
  """
  @callback map(wrapper :: t(), (sensitive_data_orig -> sensitive_data_transformed), wrap_opts()) ::
              t()
            when sensitive_data_orig: term(), sensitive_data_transformed: term()

  @doc """
  Returns the result of the callback invoked with the sensitive term.

  Executes the provided function with the sensitive term provided as the function argument, ensuring no data leaks in case of error.

  The unwrapped result of the callback exeution is then returned.
  """
  @callback exec(wrapper :: t(), (sensitive_data -> result), exec_opts()) :: result
            when sensitive_data: term(), result: term()

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
    do: SensitiveData.exec(fn -> apply(mod, :wrap, [raw_data | [opts]]) end)

  defmacro __using__(opts) do
    allow_instance_label = Keyword.get(opts, :allow_instance_label, false)
    allow_instance_redactor = Keyword.get(opts, :allow_instance_redactor, false)

    quote bind_quoted: [
            allow_instance_label: allow_instance_label,
            allow_instance_redactor: allow_instance_redactor
          ] do
      @behaviour SensitiveData.Wrapper

      require SensitiveData.Guards
      require Logger

      alias SensitiveData.Guards

      @allowable_opts [:label, :redactor]
      @instance_label_allowed allow_instance_label
      @instance_redactor_allowed allow_instance_redactor

      @typedoc ~s"""
      An instance of this wrapper.
      """
      @opaque t :: %__MODULE__{}

      @derive {Inspect, only: [:label, :redacted], optional: [:label, :redacted]}
      defstruct [:redacted, :label, :__priv__]

      @public_fields [:label, :redactor]

      @doc """
      Wraps the sensitive `term` to prevent unwanted data leaks.

      See `c:SensitiveData.Wrapper.wrap/2`.
      """
      @impl SensitiveData.Wrapper
      @spec wrap(term, list) :: t()
      def wrap(term, opts \\ []),
        do: SensitiveData.Wrapper.Impl.wrap(term, into: {__MODULE__, filter_wrap_opts(opts)})

      @doc false
      @spec filter_wrap_opts(Keyword.t()) :: SensitiveData.Wrapper.wrap_opts()
      def filter_wrap_opts(opts) when is_list(opts) do
        filtered = SensitiveData.Wrapper.Impl.filter_opts(opts, @allowable_opts)

        {allowed, disallowed} =
          Keyword.split_with(filtered, fn {k, _v} ->
            Keyword.get([label: @instance_label_allowed, redactor: @instance_redactor_allowed], k)
          end)

        unless disallowed == [],
          do:
            Logger.warning("""
            dropping disallowed options in call to #{__MODULE__}.wrap/2:

              #{disallowed |> Keyword.keys() |> inspect()}
            """)

        allowed
      end

      @doc """
      Returns the sensitive term within `wrapper`.

      See `c:SensitiveData.Wrapper.unwrap/1`.
      """
      @impl SensitiveData.Wrapper
      @spec unwrap(t()) :: term()
      def unwrap(%__MODULE__{} = wrapper), do: SensitiveData.Wrapper.Impl.unwrap(wrapper)

      @doc """
      Transforms the sensitive term within `wrapper`.

      See `c:SensitiveData.Wrapper.map/3`.
      """
      @impl SensitiveData.Wrapper
      @spec map(t(), (term() -> term()), SensitiveData.Wrapper.wrap_opts()) :: term()
      def map(%__MODULE__{} = wrapper, fun, opts \\ []),
        do: SensitiveData.Wrapper.Impl.map(wrapper, fun, filter_wrap_opts(opts))

      @doc """
      Returns the result of executing the callback with the sensitive term within `wrapper`.

      See `c:SensitiveData.Wrapper.exec/3`.
      """
      @impl SensitiveData.Wrapper
      @spec exec(t(), (term() -> term()), SensitiveData.Wrapper.exec_opts()) :: term()
      # TODO: validate `into` opts is a valid target
      def exec(%__MODULE__{} = wrapper, fun, opts \\ []),
        do: SensitiveData.Wrapper.Impl.exec(wrapper, fun, opts)

      @doc """
      Returns the redacted equivalent of the sensitive term within `wrapper`.

      See `c:SensitiveData.Wrapper.to_redacted/1`.
      """
      @impl SensitiveData.Wrapper
      @spec to_redacted(t()) :: term()
      def to_redacted(%__MODULE__{} = wrapper),
        do: SensitiveData.Wrapper.Impl.to_redacted(wrapper)
    end
  end
end
