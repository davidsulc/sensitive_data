defmodule SensitiveData.Wrapper do
  @moduledoc """
  A wrapper for sensitive data.
  """

  @typedoc """
  A wrapper containing sensitive data.
  """
  @opaque t() :: map()

  @callback wrap(term(), Keyword.t()) :: t()

  @callback unwrap(t()) :: term()

  defmacro __using__(macro_opts) do
    allowed_macro_opts = [:default_label, :default_redactor]

    quote bind_quoted: [
            allowed_macro_opts: allowed_macro_opts,
            macro_opts: macro_opts
          ] do
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

      @spec wrap(term, list) :: t()
      def wrap(term, opts \\ []) do
        opts =
          @default_opts
          |> Keyword.merge(opts)
          |> Keyword.put(:into, __MODULE__)

        SensitiveData.Wrapper.Impl.wrap(term, opts)
      end

      @spec unwrap(t()) :: term()
      def unwrap(%__MODULE__{} = wrapper), do: SensitiveData.Wrapper.Impl.unwrap(wrapper)
    end
  end
end
