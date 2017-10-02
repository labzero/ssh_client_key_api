# SSHClientKeyApi

Simple Elixir implementation for the Erlang `ssh_client_key_api` behavior, to
make it easier to specify SSH keys and `known_hosts` files independently of
any particular user's home directory.

By itself, `ssh_client_key_api` does not provide SSH functionality, it only adds
a way to send private key information to an ssh connection. It is meant to be
used alongside an SSH library such as `:ssh`, `SSHex`, `SSHKit` or the like.

## Installation

The package can be installed by adding `ssh_client_key_api` to your list of
dependencies in `mix.exs`:

```elixir
  def deps do
    [{:ssh_client_key_api, "~> 0.0.1"}]
  end
```

## Using SSHClientKeyApi

Options

 * `identity`: `IO.device` providing the ssh private key (required)
 * `known_hosts`: `IO.device` providing the known hosts list. If providing a File IO, it should have been opened in `:write` mode (required)
 * `silently_accept_hosts`: `boolean` silently accept and add new hosts to the known hosts. By default only known hosts will be accepted.

`SSHClientKeyApi` is meant to primarily be used via the convenience function
`with_config`:

```elixir
  key = File.open!("path/to/keyfile.pub")
  known_hosts = File.open!("path/to/known_hosts")
  cb = SSHClientKeyAPI.with_options(identity: key, known_hosts: known_hosts, silently_accept_hosts: true)
```

The result can then be passed as an option when creating an SSH connection.

### SSHKit

```
  connection = SSHKit.SSH.connect("example.com", key_cb: cb)
  # or with a SSHKit.Context:
  context = SSHKit.context("example.com", key_cb: cb)
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/ssh_client_key_api](https://hexdocs.pm/ssh_client_key_api).

