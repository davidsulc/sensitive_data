defmodule SensitiveData.Wrapper.Impl do
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

  @spec wrap(term, list) :: struct()
  def wrap(term, opts) when is_list(opts) do
    SensitiveData.execute(fn ->
      Keyword.fetch!(opts, :into)
      |> struct!(into_struct_shape(opts))
      |> update_data_payload(fn _ -> term end, opts)
    end)
  end

  defp into_struct_shape(opts) do
    %{
      label: Keyword.get(opts, :label),
      __priv__: PrivateData.new!(opts)
    }
  end

  defp update_data_payload(%{} = wrapper, updater_fun, opts)
       when is_sensitive(wrapper) and is_function(updater_fun, 1) do
    updated_data = SensitiveData.execute(fn -> wrapper |> unwrap() |> updater_fun.() end)

    new_label = Keyword.get(opts, :label, wrapper.label)
    new_redactor = Keyword.get(opts, :redactor, wrapper.__priv__.redactor)

    updated_wrapper = %{
      wrapper
      | label: new_label,
        __priv__: %{
          wrapper.__priv__
          | data_provider: fn -> updated_data end,
            data_type: data_type(updated_data),
            redactor: new_redactor
        }
    }

    %{updated_wrapper | redacted: to_redacted(updated_wrapper)}
  end

  @spec unwrap(struct()) :: term()
  def unwrap(%{} = wrapper) when is_sensitive(wrapper),
    do: wrapper.__priv__.data_provider.()

  # TODO FIXME
  defp to_redacted(_term), do: SensitiveData.Redacted
end
