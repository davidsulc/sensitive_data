defmodule SensitiveData.Wrapper.Impl do
  @moduledoc false

  defmodule PrivateData do
    @moduledoc false

    @derive {Inspect, only: []}
    defstruct [
      :data_type,
      data_provider: &__MODULE__.data_provider_placeholder/0,
      structure: SensitiveData
    ]

    def new!() do
      %__MODULE__{}
    end

    @doc false
    # This is used only so that we have a default value that works,
    # allowing us to call map/3 during "construction"
    def data_provider_placeholder(), do: nil
  end

  import SensitiveData.DataType, only: [data_type: 1]
  import SensitiveData.Guards, only: [is_sensitive: 1]

  require Logger

  alias SensitiveData.InvalidIntoOptionError
  alias SensitiveData.Redacted
  alias SensitiveData.Wrapper

  @wrapper_opts_names [:label]

  @spec from(function(), Keyword.t()) :: Wrapper.t()
  def from(provider, opts) when is_function(provider, 0) and is_list(opts) do
    SensitiveData.exec(fn ->
      term = provider.()

      {wrapper_mod, wrapper_opts} =
        case Keyword.fetch!(opts, :into) do
          {mod, opts} when is_atom(mod) and is_list(opts) -> {mod, opts}
          mod when is_atom(mod) -> {mod, []}
          _ -> raise InvalidIntoOptionError
        end

      unless wrapper_like_module?(wrapper_mod), do: raise(InvalidIntoOptionError)

      filtered_opts =
        try do
          filter_wrap_opts(wrapper_opts, wrapper_mod)
        rescue
          _ -> raise InvalidIntoOptionError
        end

      wrapper =
        wrapper_mod
        |> struct!(into_struct_shape(filtered_opts))
        |> map(fn _ -> term end, filtered_opts)

      unless is_sensitive(wrapper), do: raise(InvalidIntoOptionError)

      wrapper
    end)
  end

  # this doesn't guarantee that `true` comes from a proper wrapper module
  @spec wrapper_like_module?(term()) :: boolean()
  defp wrapper_like_module?(name) when is_atom(name) do
    # required from function_exported? to work properly
    # note that `name` may not be a module!
    _ = Code.ensure_loaded(name)
    function_exported?(name, :from, 2)
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
        dropping invalid wrapper options:

          #{dropped |> Keyword.keys() |> inspect()}
        """)

    filtered
  end

  @spec into_struct_shape(Wrapper.wrap_opts()) :: map()
  defp into_struct_shape(opts) do
    %{
      label: Keyword.get(opts, :label),
      __priv__: PrivateData.new!()
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

    new_label = Keyword.get(filtered_opts, :label, wrapper.label)

    updated_data = SensitiveData.exec(fn -> wrapper |> unwrap() |> fun.() end)

    redacted =
      try do
        case apply(wrapper_mod, :__sensitive_data_redactor__, []) do
          nil -> nil
          {mod_name, fn_name} -> apply(mod_name, fn_name, [updated_data])
          fn_name -> apply(wrapper_mod, fn_name, [updated_data])
        end
      rescue
        _ -> Redacted
      end

    %{
      wrapper
      | label: new_label,
        redacted: redacted,
        __priv__: %{
          wrapper.__priv__
          | data_provider: fn -> updated_data end,
            data_type: data_type(updated_data)
        }
    }
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

  @spec unwrap(struct()) :: term()
  defp unwrap(%{} = wrapper) when is_sensitive(wrapper),
    do: wrapper.__priv__.data_provider.()
end
