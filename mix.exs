defmodule SensitiveData.MixProject do
  use Mix.Project

  def project do
    [
      app: :sensitive_data,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      docs: [
        groups_for_modules: [
          Redaction: [
            SensitiveData.Redacted,
            SensitiveData.Redaction,
            SensitiveData.Redactors.Exception,
            SensitiveData.Redactors.Stacktrace
          ]
        ],
        extras: [
          "README.md",
          "pages/getting_started.md",
          "pages/cheatsheet.cheatmd",
          "pages/guiding_principles.md",
          "pages/data_leak_prevention.md"
        ]
      ],
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: [
        ignore_modules: [
          SensitiveData.Wrapper.Impl.PrivateData,
          Support.Exceptions,
          ~r/^SensitiveData\.DataType\../,
          ~r/^Inspect./
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:stream_data, "~> 0.6", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description() do
    "A library for manipulating sensitive/private/confidential data and preventing data leaks."
  end

  defp package() do
    [
      files: ~w(lib pages .formatter.exs mix.exs README*),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/davidsulc/sensitive_data"},
      source_url: "https://github.com/davidsulc/sensitive_data"
    ]
  end
end
