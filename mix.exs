defmodule UeberauthAsgard.MixProject do
  use Mix.Project

  @project_url "https://github.com/chapterspot/ueberauth_asgard"
  @version "0.1.0"

  def project do
    [
      app: :ueberauth_asgard,
      version: @version,
      elixir: "~> 1.6",
      name: "Asgard Ueberauth Strategy",
      source_url: @project_url,
      homepage_url: @project_url,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :httpoison, :ueberauth],
      mod: {UeberauthAsgard, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.0"},
      {:ueberauth, "~> 0.3"},
      {:jose, "~> 1.8"},
      {:httpoison, "~> 1.0"},
      {:poison, "~> 3.1"}
    ]
  end
end
