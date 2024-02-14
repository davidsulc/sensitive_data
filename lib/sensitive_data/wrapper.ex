defmodule SensitiveData.Wrapper do
  @moduledoc """
  Defines a wrapper for sensitive data.

  [//]: # (This is used in an HTML anchor: if updated, update links with)
  [//]: # (#module-labeling-and-redacting in the URL)

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
  A module implementing the `c:from/2` callback.
  """
  @type wrapper_module :: atom()

  @typedoc """
  Wrapping options.

  See `c:SensitiveData.Wrapper.from/2`.
  """
  @type wrap_opts :: [label: term(), redactor: Redaction.redactor()]

  @typedoc """
  Execution options.

  See `c:SensitiveData.Wrapper.exec/3`.
  """
  @type exec_opts :: [into: spec()]

  @doc """
  Wraps the sensitive term returned by the callback to prevent unwanted data
  leaks.

  The callback is executed only once during wrapper instanciation.

  ## Options

  - `:label` - a label displayed when the wrapper is inspected
  - `:redactor` - a redaction function returning the redacted equivalent of the
    given term

  TODO label & redactor options are only available if configured in `Wrapper` `use`

  ## Examples

      MySensitiveData.from(fn -> "foo" end)
      # #MySensitiveData<...>

      MySensitiveData.from(fn -> "123451234512345" end, label: :credit_card_user_bob)
      # #MySensitiveData<label: :credit_card_user_bob, ...>

      MySensitiveData.wrap(fn -> "123451234512345" end, label: :credit_card_user_bob,
        redactor: fn credit_card_number ->
          digits = String.split(credit_card_number, "", trim: true)
          {to_redact, last} = Enum.split(digits, length(digits) - 4)
          IO.iodata_to_binary([String.duplicate("*", length(to_redact)), last])
        end)
      # #MySensitiveData<redacted: "***********2345",
          label: :credit_card_user_bob, ...>
  """
  @callback from(function(), wrap_opts()) :: t()

  @doc """
  Wraps the sensitive `term` to prevent unwanted data leaks.

  > ### Prefer Using From {: .tip}
  >
  > Calling this function should be discouraged: `c:from/2` should be used instead
  > to wrap sensitive data, as in all cases where you would call `wrap(my_value)`
  > you should instead call `from(fn -> my_value end)`.

  The reason for this preference for `from/2` is that it is much harder to
  accidentally misuse. For example, `wrap(get_credit_card_number())` and
  `from(get_credit_card_number)` look very similar, but if `get_credit_card_number/0`
  raises and leaks sensitive data when it does, the call to `wrap/1` will raise and
  expose sensitive information whereas the call to `from/1` will not. This is because
  `from/2` internally wraps callback execution within `SensitiveData.exec/2`.

  Additionally, making use of `wrap/2` means you have access to unwrapped sensitive
  data, which should be discouraged: regardless of whether this sensitive data was
  fetched, generated, or derived, this should be done via functions from this library.
  Put another way, obtaining sensitive data and only then stuffing it into a wrapper
  is an anti-pattern that shouldn't be encouraged, and `wrap/2` facilitates it.

  ## Options

  See `c:from/2`

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

  By default, this optional callback will not be generated when `SensitiveData.Wrapper`
  is `use`d.

  > ### Avoid Unwrapping Sensitive Data {: .warning}
  >
  > Calling this function should be discouraged: `c:exec/3` should be used instead
  > to interact with sensitive data.

  You can always obtain the raw sensitive data via `exec(& &1)` but should seriously
  reconsider if that's needed: usually a combination of `map/2` and `exec/2` should
  satisfy all your needs regarding sensitive data interaction, and sensitive data
  typically never needs to be extracted from wrappers.
  """
  @callback unwrap(wrapper :: t()) :: term()

  @doc """
  Returns the result of the callback invoked with the sensitive term.

  Executes the provided function with the sensitive term provided as the function argument, ensuring no data leaks in case of error.

  The unwrapped result of the callback exeution is then returned.

  TODO document into option
  TODO label & redactor options are only available if configured in `Wrapper` `use`
  """
  @callback exec(wrapper :: t(), (sensitive_data -> result), exec_opts()) :: result
            when sensitive_data: term(), result: term()

  @doc """
  Invokes the callback on the wrapped sensitive term and returns the wrapped result.

  TODO document into option
  TODO label & redactor options are only available if configured in `Wrapper` `use`
  """
  @callback map(wrapper :: t(), (sensitive_data_orig -> sensitive_data_transformed), wrap_opts()) ::
              t()
            when sensitive_data_orig: term(), sensitive_data_transformed: term()

  @doc """
  Returns a redacted equivalent of the provided sensitive `term`.

  > #### Beware {: .warning}
  >
  > If you use a custom redaction strategy, you must ensure it won't leak any
  > sensitive data under any circumstances.

  The redacted value will be maintained as a field within the wrapper (see
  [labeling and redacting section](#module-labeling-and-redacting))
  and can be used to assist in determining what the wrapped sensitive value
  was then the wrapper is inspected (manually when debugging, via Observer,
  dumped in crashes, and so on).

  ## Example

      defmodule CreditCard do
        use SensitiveData.Wrapper

        def redactor(card_number) do
          {to_mask, last_four} = String.split_at(card_number, -4)
          String.duplicate("*", String.length(to_mask)) <> last_four
        end
      end

      iex(1)> CreditCard.from(fn -> "123451234512345" end)
      #CreditCard<redacted: "1**********2345", ...>
  """
  @callback redactor(term()) :: term()

  @doc """
  Returns a label to describe the given sensitive `term`.

  > #### Beware {: .warning}
  >
  > If you use a labeler, you must ensure it won't leak any
  > sensitive data under any circumstances.

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

      DatabaseCredentials.from(fn -> %{username: "foo", password: "bar"} end)
      # #DatabaseCredentials<label: :credit_card_user_bob, ...>
  """
  @callback labeler(term()) :: term()

  @optional_callbacks labeler: 1, redactor: 1, unwrap: 1, wrap: 2

  defmacro __using__(opts) do
    allow_instance_label = Keyword.get(opts, :allow_instance_label, false)
    allow_instance_redactor = Keyword.get(opts, :allow_instance_redactor, false)
    gen_unwrap = Keyword.get(opts, :unwrap, false)
    gen_wrap = Keyword.get(opts, :unwrap, false)

    quote bind_quoted: [
            allow_instance_label: allow_instance_label,
            allow_instance_redactor: allow_instance_redactor,
            gen_unwrap: gen_unwrap,
            gen_wrap: gen_wrap
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
      Wraps the result of the given callback.

      See `c:SensitiveData.Wrapper.wrap/2`.
      """
      @impl SensitiveData.Wrapper
      @spec from(function, list) :: t()
      def from(provider, opts \\ []) when is_function(provider) and is_list(opts),
        do:
          SensitiveData.Wrapper.Impl.from(provider,
            into: {__MODULE__, filter_wrap_opts(opts)}
          )

      if gen_wrap do
        @doc """
        Wraps `term`.

        See `c:SensitiveData.Wrapper.wrap/2`.
        """
        @impl SensitiveData.Wrapper
        @spec wrap(term, list) :: t()
        def wrap(term, opts \\ []),
          do: from(fn -> term end, opts)
      end

      @doc false
      @spec filter_wrap_opts(Keyword.t()) :: SensitiveData.Wrapper.wrap_opts()
      def filter_wrap_opts(opts) when is_list(opts) do
        filtered = SensitiveData.Wrapper.Impl.filter_opts(opts, @allowable_opts)

        # Keyword.split_with/2 was only introduced in 1.15.0
        {allowed, disallowed} =
          Enum.reduce(filtered, {[], []}, fn {k, _v} = pair, {acc_allow, acc_disallow} ->
            case Keyword.get(
                   [label: @instance_label_allowed, redactor: @instance_redactor_allowed],
                   k
                 ) do
              true -> {[pair | acc_allow], acc_disallow}
              _ -> {acc_allow, [pair | acc_disallow]}
            end
          end)

        unless disallowed == [],
          do:
            Logger.warning("""
            dropping disallowed options in call to #{__MODULE__}.wrap/2:

              #{disallowed |> Keyword.keys() |> inspect()}
            """)

        allowed
      end

      if gen_unwrap do
        @doc """
        Returns the sensitive term within `wrapper`.

        See `c:SensitiveData.Wrapper.unwrap/1`.
        """
        @impl SensitiveData.Wrapper
        @spec unwrap(t()) :: term()
        def unwrap(%__MODULE__{} = wrapper), do: exec(wrapper, & &1)
      end

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
    end
  end
end
