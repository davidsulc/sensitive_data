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
    # allowing us to call SensitiveData.Wrapper.Impl.update_data_payload/2
    # within SensitiveData.Wrapper.Impl.wrap/2 (i.e. during "construction")
    def data_provider_placeholder(), do: nil
  end

  import SensitiveData.DataType, only: [data_type: 1]
  import SensitiveData.Guards, only: [is_sensitive: 1]

  alias SensitiveData.Redaction
  alias SensitiveData.Wrapper

  @spec wrap(term, Keyword.t()) :: Wrapper.t()
  def wrap(term, opts) when is_list(opts) do
    SensitiveData.execute(fn ->
      into = Keyword.fetch!(opts, :into)

      with {:ok, {wrapper_mod, wrapper_opts}} <- Wrapper.spec(into) do
        wrapper_mod
        |> struct!(into_struct_shape(wrapper_opts))
        |> update_data_payload(fn _ -> term end)
      else
        {:error, e} -> raise e
      end
    end)
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

  @spec update_data_payload(
          Wrapper.t(),
          (existing_value :: term() -> new_value :: term()),
          Keyword.t()
        ) :: Wrapper.t()
  defp update_data_payload(wrapper, fun, opts \\ [])
       when is_sensitive(wrapper) and is_function(fun, 1) do
    updated_data = SensitiveData.execute(fn -> wrapper |> unwrap() |> fun.() end)

    new_label = get_label(wrapper, opts, updated_data)
    new_redactor = get_redactor(wrapper, opts)

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

  @spec get_label(Wrapper.t(), Keyword.t(), term()) :: term()
  defp get_label(wrapper, opts, updated_data) when is_sensitive(wrapper) and is_list(opts) do
    with nil <- Keyword.get(opts, :label),
         nil <- wrapper.label do
      labeler = get_fun_or_default(wrapper, :labeler)
      labeler.(updated_data)
    end
  end

  @spec get_redactor(Wrapper.t(), Keyword.t()) :: Redaction.redactor()
  defp get_redactor(wrapper, opts) when is_sensitive(wrapper) and is_list(opts) do
    with nil <- Keyword.get(opts, :redactor),
         nil <- wrapper.__priv__.redactor do
      get_fun_or_default(wrapper, :redactor)
    end
  end

  @spec get_fun_or_default(Wrapper.t(), atom()) :: (term() -> term())
  defp get_fun_or_default(wrapper, fun_name) when is_sensitive(wrapper) and is_atom(fun_name) do
    %mod{} = wrapper

    case(function_exported?(mod, fun_name, 1)) do
      true -> fn term -> apply(mod, fun_name, [term]) end
      false -> fn _ -> nil end
    end
  end

  @spec unwrap(struct()) :: term()
  def unwrap(%{} = wrapper) when is_sensitive(wrapper),
    do: wrapper.__priv__.data_provider.()

  @spec to_redacted(struct()) :: term()
  def to_redacted(%{} = wrapper) when is_sensitive(wrapper), do: wrapper.redacted
end
