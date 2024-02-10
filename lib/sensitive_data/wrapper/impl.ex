defmodule SensitiveData.Wrapper.Impl do
  @moduledoc false

  defmodule PrivateData do
    @moduledoc false

    @derive {Inspect, only: []}
    defstruct [
      :data_type,
      :redactor,
      data_provider: &__MODULE__.data_provider_placeholder/0,
      structure: SensitiveData
    ]

    def new!(args) do
      %__MODULE__{redactor: Keyword.get(args, :redactor)}
    end

    @doc false
    # This is used only so that we have a default value that works,
    # allowing us to call map/3 during "construction"
    def data_provider_placeholder(), do: nil
  end

  import SensitiveData.DataType, only: [data_type: 1]
  import SensitiveData.Guards, only: [is_sensitive: 1]

  require Logger

  alias SensitiveData.Redaction
  alias SensitiveData.Wrapper

  @wrapper_opts_names [:label, :redactor]

  @spec wrap(term, Keyword.t()) :: Wrapper.t()
  def wrap(term, opts) when is_list(opts) do
    raise_invalid_target = fn ->
      raise ArgumentError,
        message: "provided `:into` opts did not result in a valid wrapper"
    end

    SensitiveData.exec(fn ->
      {wrapper_mod, wrapper_opts} =
        case Keyword.fetch!(opts, :into) do
          {mod, opts} when is_atom(mod) and is_list(opts) -> {mod, opts}
          mod when is_atom(mod) -> {mod, []}
          _ -> raise_invalid_target.()
        end

      filtered_opts =
        try do
          filter_wrap_opts(wrapper_opts, wrapper_mod)
        rescue
          _ -> raise_invalid_target.()
        end

      wrapper =
        wrapper_mod
        |> struct!(into_struct_shape(filtered_opts))
        |> map(fn _ -> term end, filtered_opts)

      unless is_sensitive(wrapper), do: raise_invalid_target.()

      wrapper
    end)
  end

  @doc false
  @spec filter_wrap_opts(Keyword.t(), module()) :: SensitiveData.Wrapper.wrap_opts()
  def filter_wrap_opts(opts, wrapper_mod),
    do: apply(wrapper_mod, :filter_wrap_opts, [filter_opts(opts, @wrapper_opts_names)])

  @doc false
  @spec filter_opts(Keyword.t(), [atom()]) :: SensitiveData.Wrapper.wrap_opts()
  def filter_opts(opts, allowable_opts) when is_list(opts) and is_list(allowable_opts) do
    {filtered, dropped} = Keyword.split(opts, allowable_opts)

    unless dropped == [],
      do:
        Logger.warning("""
        dropping invalid options in call to #{__MODULE__}.wrap/2:

          #{dropped |> Keyword.keys() |> inspect()}
        """)

    filtered
  end

  @spec into_struct_shape(Wrapper.wrap_opts()) :: map()
  defp into_struct_shape(opts) do
    priv_opts =
      case Keyword.get(opts, :redactor) do
        nil -> []
        redactor -> [redactor: redactor]
      end

    %{
      label: Keyword.get(opts, :label),
      __priv__: PrivateData.new!(priv_opts)
    }
  end

  @spec map(
          Wrapper.t(),
          (existing_value :: term() -> new_value :: term()),
          Keyword.t()
        ) :: Wrapper.t()
  def map(%{} = wrapper, fun, opts)
      when is_sensitive(wrapper) and is_function(fun, 1) do
    %wrapper_mod{} = wrapper

    filtered_opts = filter_wrap_opts(opts, wrapper_mod)

    updated_data = SensitiveData.exec(fn -> wrapper |> unwrap() |> fun.() end)

    new_label = get_label(wrapper, filtered_opts)
    new_redactor = get_redactor(wrapper, filtered_opts)

    %{
      wrapper
      | label: new_label,
        redacted: new_redactor.(updated_data),
        __priv__: %{
          wrapper.__priv__
          | data_provider: fn -> updated_data end,
            data_type: data_type(updated_data),
            redactor: new_redactor
        }
    }
  end

  @spec get_label(Wrapper.t(), Keyword.t()) :: term()
  defp get_label(wrapper, opts) when is_sensitive(wrapper) and is_list(opts),
    do: Keyword.get(opts, :label, wrapper.label)

  @spec get_redactor(Wrapper.t(), Keyword.t()) :: Redaction.redactor()
  defp get_redactor(wrapper, opts) when is_sensitive(wrapper) and is_list(opts) do
    with nil <- Keyword.get(opts, :redactor),
         nil <- wrapper.__priv__.redactor do
      get_fun_or_default(wrapper, :redactor, SensitiveData.Redacted)
    end
  end

  @spec get_fun_or_default(Wrapper.t(), atom(), term()) :: (term() -> term())
  defp get_fun_or_default(wrapper, fun_name, default_return_value)
       when is_sensitive(wrapper) and is_atom(fun_name) do
    %mod{} = wrapper

    case(function_exported?(mod, fun_name, 1)) do
      true -> fn term -> apply(mod, fun_name, [term]) end
      false -> fn _ -> default_return_value end
    end
  end

  @spec exec(struct(), (term() -> result)) :: result when result: term()
  def exec(%{} = wrapper, fun, opts \\ []) when is_sensitive(wrapper) do
    into_config =
      SensitiveData.exec(fn ->
        case filter_opts(opts, [:into]) |> Keyword.get(:into) do
          nil ->
            []

          {mod, wrap_opts} when is_atom(mod) and is_list(opts) ->
            # wrapper options for the `into` option must be filtered according to
            # the corresponding `into` module and NOT based on the subject `wrapper`
            # module
            [into: {mod, filter_wrap_opts(wrap_opts, mod)}]

          mod when is_atom(mod) ->
            [into: mod]
        end
      end)

    SensitiveData.exec(
      fn ->
        wrapper |> unwrap() |> fun.()
      end,
      into_config
    )
  end

  @spec to_redacted(struct()) :: term()
  def to_redacted(%{} = wrapper) when is_sensitive(wrapper), do: wrapper.redacted

  @spec unwrap(struct()) :: term()
  defp unwrap(%{} = wrapper) when is_sensitive(wrapper),
    do: wrapper.__priv__.data_provider.()
end
