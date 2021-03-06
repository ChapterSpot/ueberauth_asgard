defmodule UeberauthAsgard do
  @moduledoc false

  use Application

  def start(_type, _args) do
    children = [
      %{
        id: Ueberauth.Strategy.Asgard.JWS,
        start: {Ueberauth.Strategy.Asgard.JWS, :start_link, [:asgard_jws_cache]}
      }
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
