# Note: Logger.warn exceptions because the :ssh_client_key_api will silently
# catches exceptions
defmodule SSHClientKeyAPI do
  @external_resource "README.md"
  @moduledoc "README.md"
             |> File.read!()
             |> String.split("<!-- MDOC !-->")
             |> Enum.fetch!(1)

  require Logger
  require Record

  @behaviour :ssh_client_key_api

  @doc """
  Returns a tuple suitable for passing to `:ssh.connect/3` or
  `SSHKit.SSH.connect/2` as the `key_cb` option.

  ## Options

    * `:identity` - [`IO.device`] providing the ssh key (required)

    * `:known_hosts` - [`IO.device`] providing the known hosts list. If providing a
      File IO, it should have been opened in `:write` mode (required)

    * `:silently_accept_hosts` - [`boolean`] silently accept and add new hosts to the
      known hosts. By default only known hosts will be accepted.

    * `:passphrase` - [`binary`] passphrase if your key is protected (optional)

  By default it will use the the files found in `System.user_home!/0`.

  ## Examples

      key = File.open!("path/to/keyfile")
      known_hosts = File.open!("path/to/known_hosts")
      cb = SSHClientKeyAPI.with_options(identity: key, known_hosts: known_hosts)
      SSHKit.SSH.connect("example.com", key_cb: cb)

  """
  def with_options(opts \\ []) do
    opts = with_defaults(opts)

    opts =
      opts
      |> Keyword.put(:identity_data, IO.binread(opts[:identity], :all))
      |> Keyword.put(:known_hosts_data, IO.binread(opts[:known_hosts], :all))

    {__MODULE__, opts}
  end

  @impl :ssh_client_key_api
  def add_host_key(hostname, _port, key, opts) do
    hostname = normalize_hostname(hostname)

    case silently_accept_hosts(opts) do
      true ->
        # Don't save this to a file
        :ok

      _ ->
        # TODO: This seems to be missing a case to check if the host key is actually in the file
        message = """
        Error: unknown fingerprint found for #{inspect(hostname)} #{inspect(key)}.
        You either need to add a known good fingerprint to your known hosts file for this host,
        *or* pass the silently_accept_hosts option to your client key callback
        """

        {:error, message}
    end
  rescue
    e ->
      Logger.warn("Exception in add_host_key: #{inspect(e)}")
      raise e
  end

  @impl :ssh_client_key_api
  def is_host_key(key, host, port, alg, opts) do
    :ssh_file.is_host_key(key, host, port, alg, opts)
  rescue
    e ->
      Logger.warn("Exception in is_host_key: #{inspect(e)}")
  end

  # There's a fundamental disconnect between how the key_cb option works and how
  # we want to use it. The key_cb option is expecting us to receive the
  # algorithm type and then find the matching key, but we already know the exact
  # key we want to use. So instead we return the key for every algorithm type
  # and erlang will ignore the keys we return for an incorrect algorithm type.
  #
  # Ideally we could instead find the matching algorithm type for the key
  # provided by the user without requiring the user to manually provide the key
  # type but thus far I've been unable to find a way to find the algorithm type
  # for the key
  @impl :ssh_client_key_api
  def user_key(_alg, opts) do
    raw_key =
      opts
      |> identity_data()
      |> to_string()

    raw_key
    |> :public_key.pem_decode()
    |> List.first()
    |> case do
      {{:no_asn1, :new_openssh}, _data, :not_encrypted} ->
        :ssh_file.decode(raw_key, :public_key)
        |> case do
          [{key, _comments} | _rest] ->
            {:ok, key}

          {:error, :key_decode_failed} ->
            message =
              "unable to decode key, possibly because the key type does not support a passphrase"

            Logger.warn(message)
            {:error, :key_decode_failed}

          other ->
            Logger.warn("Unexpected return value from :ssh_file.decode/2 #{inspect(other)}")
            {:error, :ssh_client_key_api_unable_to_decode_key}
        end

      {_type, _data, :not_encrypted} = entry ->
        result = :public_key.pem_entry_decode(entry)

        {:ok, result}

      {_type, _data, {_alg, _}} = entry ->
        result = :public_key.pem_entry_decode(entry, passphrase(opts))
        {:ok, result}

      error ->
        Logger.warn("Unexpected return value from :public_key.decode/2 #{inspect(error)}")
        {:error, :ssh_client_key_api_unable_to_decode_key}
    end
  rescue
    e ->
      Logger.warn("user_key exception: #{inspect(e)}")
      raise e
  end

  defp cb_opts(opts) do
    opts[:key_cb_private]
  end

  defp known_hosts_data(opts) do
    cb_opts(opts)[:known_hosts_data]
  end

  defp known_hosts(opts) do
    cb_opts(opts)[:known_hosts]
  end

  defp silently_accept_hosts(opts) do
    cb_opts(opts)[:silently_accept_hosts]
  end

  defp identity_data(opts) do
    cb_opts(opts)[:identity_data]
  end

  defp passphrase(opts) do
    cb_opts(opts)[:passphrase]
    |> case do
      # Needs to be a charlist
      passphrase when is_list(passphrase) ->
        passphrase

      passphrase when is_binary(passphrase) ->
        Logger.warn("Passphrase must be a charlist, not a binary. Ignoring.")
        nil

      nil ->
        nil
    end
  end

  # Handles the case where the ype of hostname is
  # `[inet:ip_address() | inet:hostname()]`
  defp normalize_hostname([hostname, _ip_addr]), do: hostname
  defp normalize_hostname(hostname), do: hostname

  defp default_user_dir, do: Path.join(System.user_home!(), ".ssh")

  defp default_identity do
    default_user_dir()
    |> Path.join("id_rsa.pub")
    |> File.open!([:read])
  end

  defp default_known_hosts do
    default_user_dir()
    |> Path.join("known_hosts")
    |> File.open!([:read, :write])
  end

  defp with_defaults(opts) do
    opts
    |> Keyword.put_new_lazy(:identity, &default_identity/0)
    |> Keyword.put_new_lazy(:known_hosts, &default_known_hosts/0)
    |> Keyword.put_new(:silently_accept_hosts, false)
  end
end
