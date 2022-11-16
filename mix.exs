defmodule SSHClientKeyAPI.Mixfile do
  use Mix.Project

  @source "https://github.com/labzero/ssh_client_key_api"
  @version "0.2.1"

  def project do
    [
      app: :ssh_client_key_api,
      version: @version,
      elixir: "~> 1.6",
      elixirc_paths: ["lib"],
      test_coverage: [tool: ExCoveralls],
      dialyzer: [plt_add_deps: :transitive],
      preferred_cli_env: [coveralls: :test],
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      deps: deps(),
      docs: docs(),
      package: package()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ssh, :public_key]
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.6.7", runtime: false, only: [:dev, :test]},
      {:dialyxir, "~> 1.2.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.6", only: :test},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false}
    ]
  end

  defp docs do
    [
      main: "SSHClientKeyAPI",
      source_url: @source,
      source_ref: "v#{@version}",
      api_references: false,
      extra_section: []
    ]
  end

  defp description do
    "An Elixir implementation of the Erlang `ssh_client_key_api` behavior."
  end

  defp package do
    [
      maintainers: ["labzero", "Sasha Voynow", "Brien Wankel"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source}
    ]
  end
end
