defmodule SSHClientKeyAPI do

  @behaviour :ssh_client_key_api
  @key_algorithms :ssh.default_algorithms()[:public_key]

  @moduledoc ~S"""

  Simple wrapper for the Erlang `:ssh_client_key_api` behavior, to
  make it easier to specify SSH keys and `known_hosts` files independently of
  any particular user's home directory

  It is meant to primarily be used via the convenience function `with_options`:

  ```
  key = File.open!("path/to/keyfile")
  known_hosts = File.open!("path/to/known_hosts")
  cb = SSHClientKeyAPI.with_options(identity: key, known_hosts: known_hosts, silently_accept_hosts: true)
  ```

  The result can be passed as an option when creating an `SSHKit.SSH.Connection`:

  ```
  SSHKit.SSH.connect("example.com", key_cb: cb)
  ```

    - `identity`: `IO.device` providing the ssh key (required)
    - `known_hosts`: `IO.device` providing the known hosts list. If providing a File IO, it should have been opened in `:write` mode (required)
    - `silently_accept_hosts`: `boolean` silently accept and add new hosts to the known hosts. By default only known hosts will be accepted.
  """

  @spec with_options(opts :: list) :: {atom, list}
  @doc """
    returns a tuple suitable for passing the `SSHKit.SSH.Connect` as the `key_cb` option.

    ### Options

    - `identity`: `IO.device` providing the ssh key (required)
    - `known_hosts`: `IO.device` providing the known hosts list. If providing a File IO, it should have been opened in `:write` mode (required)
    - `silently_accept_hosts`: `boolean` silently accept and add new hosts to the known hosts. By default only known hosts will be accepted.
    - `passphrase` : `binary` passphrase if your key is protected (optional)

     by default it will use the the files found in `System.user_home!`

    ### Example

    ```
    key = File.open!("path/to/keyfile")
    known_hosts = File.open!("path/to/known_hosts")
    cb = SSHClientKeyAPI.with_options(identity: key, known_hosts: known_hosts)
    SSHKit.SSH.connect("example.com", key_cb: cb)
    ```

  """
  def with_options(opts \\ []) do
      opts = with_defaults(opts)
      opts =
        opts
        |> Keyword.put(:identity_data, IO.binread(opts[:identity], :all))
        |> Keyword.put(:known_hosts_data, IO.binread(opts[:known_hosts], :all))
    {__MODULE__, opts}
  end

  def add_host_key(hostname, key, opts) do
    case silently_accept_hosts(opts) do
      true ->
        opts
        |> known_hosts_data
        |> :public_key.ssh_decode(:known_hosts)
        |> (fn decoded -> decoded ++ [{key, [{:hostnames, [hostname]}]}] end).()
        |> :public_key.ssh_encode(:known_hosts)
        |> (fn encoded -> IO.binwrite(known_hosts(opts), encoded) end).()
      _ ->
        message =
          """
          Error: unknown fingerprint found for #{inspect hostname} #{inspect key}.
          You either need to add a known good fingerprint to your known hosts file for this host,
          *or* pass the silently_accept_hosts option to your client key callback
          """
        {:error, message}
    end
  end

  def is_host_key(key, hostname, alg, opts) when alg in @key_algorithms do
    silently_accept_hosts(opts) || opts
    |> known_hosts_data
    |> to_string
    |> :public_key.ssh_decode(:known_hosts)
    |> has_fingerprint(key, hostname)
  end

  def is_host_key(_, _, alg, _) do
    IO.puts("unsupported host key algorithm #{inspect alg}")
    false
  end

  def user_key(alg, opts) when alg in @key_algorithms do
      opts
      |> identity_data
      |> to_string
      |> :public_key.pem_decode
      |> List.first
      |> decode_pem_entry(Keyword.get(opts, :passphrase))
  end

  def user_key(alg, _) do
    message = "unsupported user key algorithm #{inspect alg}"
    IO.puts(message)
    {:error, message}
  end

  defp decode_pem_entry({_type, _data, :not_encrypted} = entry, _) do
    {:ok, :public_key.pem_entry_decode(entry)}
  end

  defp decode_pem_entry({_type, _data, _cipher_info}, nil) do
    {:error, "passphrase needed for protected key"}
  end

  defp decode_pem_entry({_type, _data, _cipher_info} = entry, phrase) do
      {:ok, :public_key.pem_entry_decode(entry, phrase)}
  rescue
    _e in MatchError -> {:error, "passphrase for protected key is invalid"}
  end

  defp identity_data(opts) do
    cb_opts(opts)[:identity_data]
  end

  defp silently_accept_hosts(opts) do
    cb_opts(opts)[:silently_accept_hosts]
  end

  defp known_hosts(opts) do
    cb_opts(opts)[:known_hosts]
  end

  defp known_hosts_data(opts) do
    cb_opts(opts)[:known_hosts_data]
  end

  defp cb_opts(opts) do
    opts[:key_cb_private]
  end

  defp has_fingerprint(fingerprints, key, hostname) do
    Enum.any?(fingerprints,
      fn {k, v} -> (k == key) && (Enum.member?(v[:hostnames], hostname)) end
      )
  end

  defp default_user_dir, do: Path.join(System.user_home!, ".ssh")

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
