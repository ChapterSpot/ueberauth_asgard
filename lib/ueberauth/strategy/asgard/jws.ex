defmodule UeberauthAsgard.Strategy.Asgard.JWS do
  use GenServer
  require Logger

  def start_link(table_name) do
    GenServer.start_link(__MODULE__, table_name, name: __MODULE__)
  end

  def get_jwk_by_kid(kid, default_value_function) do
    case get(kid) do
      {:not_found} -> set(kid, default_value_function.())
      {:found, result} -> result
    end
  end

  defp get(kid) do
    case GenServer.call(__MODULE__, {:get, kid}) do
      [] -> {:not_found}
      [{_kid, result}] -> {:found, result}
    end
  end

  defp set(kid, jwk), do: GenServer.call(__MODULE__, {:set, kid, jwk})

  # --- callbacks

  def handle_call({:get, kid}, _from, state) do
    %{ets_table_name: ets_table_name} = state
    result = :ets.lookup(ets_table_name, kid)

    {:reply, result, state}
  end

  def handle_call({:set, kid, jwk}, _from, state) do
    %{ets_table_name: ets_table_name} = state
    true = :ets.insert(ets_table_name, {kid, jwk})

    {:reply, jwk, state}
  end

  def init(ets_table_name) do
    result = :ets.new(ets_table_name, [:named_table, :set, :private])

    Logger.debug("#{__MODULE__} ETS Table Created: #{inspect(result)}")

    {:ok, %{ets_table_name: ets_table_name}}
  end
end
