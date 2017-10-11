defmodule SSHClientKeyApi.Mixfile do
  use Mix.Project


  @version "0.1.1"
  @source "https://github.com/labzero/ssh_client_key_api"


  def project do
    [app: :ssh_client_key_api,
     version: @version,
     elixir: "~> 1.3",
     elixirc_paths: ["lib"],
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     source_url: @source,
     docs: [source_ref: "v#{@version}", main: "readme", extras: ["README.md"]],
     description: description(),
     deps: deps(),
     package: package()]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [{:credo, "~> 0.8", runtime: false, only: [:dev, :test]},
     {:ex_doc, "~> 0.16", runtime: false, only: [:dev]}]
  end

  defp description do
    "An Elixir implementation of the Erlang `ssh_client_key_api` behavior."
  end

  defp package do
    [maintainers: ["labzero", "Sasha Voynow", "Brien Wankel"],
     licenses: ["MIT"],
     links: %{"GitHub" => @source}]
  end
end
