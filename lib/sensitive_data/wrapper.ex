defmodule SensitiveData.Wrapper do
  @moduledoc """
  Defines a wrapper for sensitive data.

  [//]: # (This is used in an HTML anchor: if updated, update links with)
  [//]: # (#module-using)

  ## Using

  When used, this module will implement the callbacks from this
  `SensitiveData.Wrapper` module, making the module where the `use`
  call is made into a sensitive data wrapper.

  ```
  defmodule MySensitiveData do
    use SensitiveData.Wrapper
  end
  ```

  The options when using are:

  - `:allow_label` - a boolean indicating whether the `:label` option
    is allowed on instance wrappers (see for example `c:from/2`).
    Defaults to `false`.
    This option should be used with care, see
    [Redacting and Labeling](#module-redacting-and-labeling))
  - `:redactor` - a `t:function_handle/0` pointing to a
    `t:SensitiveData.Redaction.redactor/1` function (for any wrapped
    `t:term/0`) able to appropriately redact the wrapped sensitive
    term for display (such as via `inspect/1`).
    By default, no redacted value is made available.
    If the redactor function fails (e.g., by raising), the redacted
    value will be set to `SensitiveData.Redacted`.
    This option should be used with care, see
    [redacting and labeling section](#module-redacting-and-labeling))
  - `:exception_redactor` - a `t:function_handle/0` pointing to a
    `t:SensitiveData.Redaction.exception_redactor/0`.
    By default, exception redaction is provided by `SensitiveData.Redactors.Exception.drop/1`.
    This option should be used with care, see [Custom Failure Redaction](#module-custom-failure-redaction)
  - `:stacktrace_redactor` - a `t:function_handle/0` pointing to a
    `t:SensitiveData.Redaction.stacktrace_redactor/0`.
    By default, stack trace redaction is provided by `SensitiveData.Redactors.Stacktrace.strip/1`.
    This option should be used with care, see [Custom Failure Redaction](#module-custom-failure-redaction)
  - `:wrap` - a boolean indicating whether the `c:wrap/2` callback implementation
    should be generated. Defaults to `false`.
  - `:unwrap` - a boolean indicating whether the `c:unwrap/1` callback implementation
    should be generated. Defaults to `false`.

  [//]: # (This is used in an HTML anchor: if updated, update links with)
  [//]: # (#module-redacting-and-labeling)

  ## Redacting and Labeling

  It can be helpful to have some contextual information about the sensitive data contained
  within a wrapper. Aside from [guards](SensitiveData.Guards.html), you may wish to make
  use of:
  - redaction at the module level (i.e., single shared redaction logic for all terms
    wrapped by the same module)
  - labels at the instance level (i.e., each wrapper instance can have its own different
    label)

  > #### Beware {: .warning}
  >
  > Redacting and labeling should be used with utmost care to ensure they won't leak any
  > sensitive data under any circumstances.
  >
  > **If you use a custom redaction strategy**, you must ensure it won't leak sensitive
  > information for any possible sensitive term wrapped by the module.
  >
  > **If you allow labeling**, you must ensure that any call site setting a label is doing so
  > without leaking sensitive data.

  ### Examples

      defmodule CreditCard do
        use SensitiveData.Wrapper, allow_label: true, redactor: :redactor

        def redactor(card_number) when is_binary(card_number) do
          {<<first_number::binary-1, to_mask::binary>>, last_four} = String.split_at(card_number, -4)
          IO.iodata_to_binary([first_number, List.duplicate("*", String.length(to_mask)), last_four])
        end
      end

      # in IEx:
      CreditCard.from(fn -> "5105105105105100" end, label: {:type, :debit})
      #CreditCard<redacted: "5***********5100", label: {:type, :debit}, ...>

  Both the redacted value and the label will be maintained as fields within
  the wrapper
  and can be used to assist in determining what the wrapped sensitive value
  was then the wrapper is inspected (manually when debugging, via Observer,
  dumped in crashes, and so on). Both values can be used in pattern matches.

  For both redacting and labeling, `nil` values will not be displayed when
  inspecting.

  [//]: # (This is used in an HTML anchor: if updated, update links with)
  [//]: # (#module-custom-failure-redaction)

  ## Custom Failure Redaction

  If an exception is raised within a sensitive context (such within `c:exec/3`, `c:from/2`,
  or `c:map/3`), both the exception and stack trace will be redacted. By default:

  - the exception will be redacted with `SensitiveData.Redactors.Exception.drop/1`
  - the stack trace will be redacted with `SensitiveData.Redactors.Stacktrace.strip/1`

  However, failure redaction can be customized via the `:exception_redactor` and
  `:stacktrace_redactor` options given to the `use` call.

  > #### Beware {: .warning}
  >
  > Custom failure redaction should be used with utmost care to ensure it won't leak any
  > sensitive data under any circumstances.
  >
  > For exception redaction, you must ensure it won't leak sensitive
  > information for any possible exception: standard Elixir ones, the ones in your code base,
  > but also any exception that may be raised from a dependency.
  >
  > For stack trace redaction, it must handle all possible stack traces.

  If a custom redactor function fails, redaction will fall back to the corresponding default
  redactor listed above.
  """

  import SensitiveData.Guards,
    only: [is_sensitive_list: 1, is_sensitive_map: 1, is_sensitive_tuple: 1]

  @typedoc """
  A wrapper containing sensitive data.

  The wrapper structure should be considered opaque, aside from the `label` and
  `redacted` fields (see
  [redacting and labeling section](#module-redacting-and-labeling)). You may
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

  @typedoc """
  The location of a function.

  If provided as an `atom`, the function is that with the same name and located in the
  current module.

  If provided as a `{module, atom}` tuple, the function is that with the same name as `atom`
  and located in the `module` module.
  """
  @type function_handle :: local_function :: atom() | {module(), remote_function :: atom()}

  @typedoc """
  A wrapper target.

  If provided as a `wrapper_module` module name, the `c:from/2` callback in the
  corresponding wrapper module will be called with default options.

  If provided as a `{wrapper_module, wrap_opts}` tuple, the `c:from/2` callback in the
  corresponding wrapper module will be called with the provided `wrap_opts` options.
  """
  @type spec :: wrapper_module() | {wrapper_module(), wrap_opts()}

  @typedoc """
  A module implementing the `SensitiveData.Wrapper` behaviour.
  """
  @type wrapper_module :: atom()

  @typedoc """
  Wrapping options.

  Allowable options are configured during `use` invocation, see
  [Using section](#module-using).

  Invalid or unsupported values will be ignored and logged.

  ## Options

  - `:label` - a label displayed when the wrapper is inspected. This option is only
    available if the `:allow_label` option was set to `true` when [using](#module-using)
    `SensitiveData.Wrapper`.
  """
  @type wrap_opts :: [label: label :: term()]

  @typedoc """
  Execution options.

  ## Options

  - `:into` - a `t:spec/0` value defining how the execution result should be wrapped.
  """
  @type exec_opts :: [into: spec()]

  @doc """
  Wraps the sensitive term returned by the callback to prevent unwanted data
  leaks.

  The callback is executed only once: during wrapper instanciation.

  ## Options

  See `t:wrap_opts/0`.

  ## Examples

      MySensitiveData.from(fn -> "foo" end)
      # #MySensitiveData<...>

      MySensitiveData.from(fn -> "5105105105105100" end, label: :credit_card_user_bob)
      # #MySensitiveData<label: :credit_card_user_bob, ...>
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

      # Not recommended
      MySensitiveData.wrap("foo")
      # #MySensitiveData<...>

      # Do this instead
      MySensitiveData.from(fn -> "foo" end)
      # #MySensitiveData<...>

      # Not recommended
      MySensitiveData.wrap("5105105105105100", label: :credit_card_user_bob)
      # #MySensitiveData<label: :credit_card_user_bob, ...>

      # Do this instead
      MySensitiveData.from(fn -> "5105105105105100" end, label: :credit_card_user_bob)
      # #MySensitiveData<label: :credit_card_user_bob, ...>
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

  You can always obtain the raw sensitive data via `exec(wrapped_value, & &1)` but should seriously
  reconsider if that's needed: usually a combination of `map/2` and `exec/2` should
  satisfy all your needs regarding sensitive data interaction, and sensitive data
  typically never needs to be extracted from wrappers.

  ## Examples

      data = MySensitiveData.from(fn -> "foo" end)

      # Not recommended
      MySensitiveData.unwrap(data)
      # "foo"

      # Do this instead if you absolutely must unwrap the value
      MySensitiveData.exec(data, & &1)
      # "foo"
  """
  @callback unwrap(wrapper :: t()) :: term()

  @doc """
  Returns the result of the callback invoked with the sensitive term.

  Executes the provided function with the sensitive term provided as the function argument,
  ensuring no data leaks in case of error.

  The unwrapped result of the callback execution is then either returned as is,
  or wrapped according to provided options.

  ## Examples

      # CreditCard implements the SensitiveData.Wrapper behaviour
      credit_card = CreditCard.from(fn -> "5105105105105100" end)

      # We can call a function that expect a credit card number (in string
      # format), and will return `%{result: :ok}` upon successful payment:
      %{result: :ok} = CreditCard.exec(credit_card, &pay_with_credit_card/1)

      # We can also alter the wrapped data without ever exposing it outside
      # of a sensitive context protecting the data from leaks:
      # PaymentToken implements the SensitiveData.Wrapper behaviour
      CreditCard.exec(credit_card, fn card_number -> tokenize(card_number) end, into: PaymentToken)
      # #PaymentToken<...>
  """
  @callback exec(wrapper :: t(), (sensitive_data -> result), exec_opts()) :: result
            when sensitive_data: term(), result: term()

  @doc """
  Invokes the callback on the wrapped sensitive term and returns the wrapped result.

  ## Options

  See `t:wrap_opts/0`.

  ## Examples

      data = MySensitiveData.from(fn -> "foo" end)

      MySensitiveData.map(data, fn orig -> orig <> "bar" end, label: :now_foobar)
      # #MySensitiveData<label: :now_foobar, ...>
  """
  @callback map(wrapper :: t(), (sensitive_data_orig -> sensitive_data_transformed), wrap_opts()) ::
              t()
            when sensitive_data_orig: term(), sensitive_data_transformed: term()

  @optional_callbacks unwrap: 1, wrap: 2

  @doc """
  Returns the length of the list wrapped within `term`.
  """
  @spec sensitive_length(t()) :: non_neg_integer()
  def sensitive_length(term) when is_sensitive_list(term), do: elem(term.__priv__.data_type, 1)

  @doc """
  Returns the size of the map wrapped within `term`.

  The size of a map is the number of key-value pairs that the map contains.

  This operation happens in constant time.
  """
  @spec sensitive_map_size(t()) :: non_neg_integer()
  def sensitive_map_size(term) when is_sensitive_map(term), do: term.__priv__.data_type.size

  @doc """
  Returns the size of a tuple wrapped within `term`.

  This operation happens in constant time.
  """
  @spec sensitive_tuple_size(t()) :: non_neg_integer()
  def sensitive_tuple_size(term) when is_sensitive_tuple(term),
    do: elem(term.__priv__.data_type, 1)

  defmacro __using__(opts) do
    allow_label = Keyword.get(opts, :allow_label, false)
    redactor = Keyword.get(opts, :redactor)
    exception_redactor = Keyword.get(opts, :exception_redactor)
    stacktrace_redactor = Keyword.get(opts, :stacktrace_redactor)
    gen_wrap = Keyword.get(opts, :wrap, false)
    gen_unwrap = Keyword.get(opts, :unwrap, false)

    quote bind_quoted: [
            allow_label: allow_label,
            redactor: redactor,
            exception_redactor: exception_redactor,
            stacktrace_redactor: stacktrace_redactor,
            gen_unwrap: gen_unwrap,
            gen_wrap: gen_wrap
          ] do
      @behaviour SensitiveData.Wrapper

      require SensitiveData.Guards
      require Logger

      alias SensitiveData.Guards

      @allowable_opts [:label]
      @instance_label_allowed allow_label

      @typedoc ~s"""
      An instance of this wrapper.
      """
      @opaque t :: %__MODULE__{}

      @derive {Inspect, only: [:label, :redacted], optional: [:label, :redacted]}
      defstruct [:redacted, :label, :__priv__]

      @doc """
      Wraps the result of the given callback.

      See `c:SensitiveData.Wrapper.wrap/2`.
      """
      @impl SensitiveData.Wrapper
      @spec from(function, SensitiveData.Wrapper.wrap_opts()) :: t()
      def from(provider, opts \\ []) when is_function(provider) and is_list(opts) do
        SensitiveData.Wrapper.Impl.from(provider, into: {__MODULE__, filter_wrap_opts(opts)})
      end

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
            case Keyword.get([label: @instance_label_allowed], k) do
              true -> {[pair | acc_allow], acc_disallow}
              _ -> {acc_allow, [pair | acc_disallow]}
            end
          end)

        unless disallowed == [],
          do:
            Logger.warning("""
            dropping disallowed wrapper options:

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
      Returns the result of executing the callback on the sensitive term, within `wrapper`.

      See `c:SensitiveData.Wrapper.exec/3`.
      """
      @impl SensitiveData.Wrapper
      @spec exec(t(), (term() -> term()), SensitiveData.Wrapper.exec_opts()) :: term()
      def exec(%__MODULE__{} = wrapper, fun, opts \\ []),
        do: SensitiveData.Wrapper.Impl.exec(wrapper, fun, opts)

      # we always implement these functions
      # That way, it's not possible (as these function aren't defoverridable) to
      # sneak in an unsafe/incorrect implementations.

      if redactor do
        def __sensitive_data_redactor__(), do: unquote(redactor)
      else
        def __sensitive_data_redactor__(), do: nil
      end

      if exception_redactor do
        def __sensitive_data_exception_redactor__(),
          do: unquote(exception_redactor)
      else
        def __sensitive_data_exception_redactor__(),
          do: {SensitiveData.Redactors.Exception, :drop}
      end

      if stacktrace_redactor do
        def __sensitive_data_stacktrace_redactor__(), do: unquote(stacktrace_redactor)
      else
        def __sensitive_data_stacktrace_redactor__(),
          do: {SensitiveData.Redactors.Stacktrace, :strip}
      end
    end
  end
end
