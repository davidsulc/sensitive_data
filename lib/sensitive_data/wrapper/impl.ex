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

    new_label = Keyword.get(opts, :label, wrapper.label)
    new_redactor = Keyword.get(opts, :redactor, wrapper.__priv__.redactor)

    %mod{} = wrapper

    redacted =
      case new_redactor do
        nil -> apply(mod, :redact_term, [updated_data])
        _ -> new_redactor.(updated_data)
      end

    %{
      wrapper
      | label: new_label,
        redacted: redacted,
        __priv__: %{
          wrapper.__priv__
          | data_provider: fn -> updated_data end,
            data_type: data_type(updated_data),
            redactor: new_redactor
        }
    }
  end

  @spec unwrap(struct()) :: term()
  def unwrap(%{} = wrapper) when is_sensitive(wrapper),
    do: wrapper.__priv__.data_provider.()

  @spec to_redacted(struct()) :: term()
  def to_redacted(%{} = wrapper) when is_sensitive(wrapper), do: wrapper.redacted
end
