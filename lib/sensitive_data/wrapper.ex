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

  @doc false
  @spec spec(Keyword.t()) :: {:ok, {atom(), Keyword.t()}} | {:error, Exception.t()}
  # TODO verify mod has wrap function, and that the result is_sensitive
  def spec({mod, opts}) when is_atom(mod) and is_list(opts), do: {:ok, {mod, opts}}
  # TODO FIXME handle error cases (nil, bad mod, etc.)
  def spec(mod) when is_atom(mod), do: spec({mod, []})

  @doc false
  @spec spec!(Keyword.t()) :: {atom(), Keyword.t()}
  def spec!(spec_info) do
    with {:ok, spec} <- spec(spec_info) do
      spec
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

      @spec to_redacted(t()) :: term()
      def to_redacted(%__MODULE__{} = wrapper),
        do: SensitiveData.Wrapper.Impl.to_redacted(wrapper)

      @spec redact_term(term()) :: term()
      def redact_term(_term), do: nil

      defoverridable redact_term: 1
    end
  end
end
