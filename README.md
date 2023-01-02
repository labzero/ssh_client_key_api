# SSHClientKeyAPI

<!-- MDOC !-->

[![Module Version](https://img.shields.io/hexpm/v/ssh_client_key_api.svg)](https://hex.pm/packages/ssh_client_key_api)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/ssh_client_key_api/)
[![Total Download](https://img.shields.io/hexpm/dt/ssh_client_key_api.svg)](https://hex.pm/packages/ssh_client_key_api)
[![License](https://img.shields.io/hexpm/l/ssh_client_key_api.svg)](https://github.com/labzero/ssh_client_key_api/blob/master/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/labzero/ssh_client_key_api.svg)](https://github.com/labzero/ssh_client_key_api/commits/master)

Simple Elixir implementation for the Erlang `:ssh_client_key_api` behavior, to
make it easier to specify SSH keys and `known_hosts` files independently of
any particular user's home directory.

By itself, `:ssh_client_key_api` does not provide SSH functionality, it only adds
a way to send private key information to an SSH connection. It is meant to be
used alongside an SSH library such as `:ssh`, `SSHex`, `SSHKit`, or the like.

Note: Upgrade to ssh_client_key_api 0.3.0 or higher for use with Erlang/OTP 25

## Supported Key Types

- rsa - with or without passphrase
- ed25519 - only supported without a passphrase
- ecdsa - only supported without a passphrase
- dsa - with or without passphrase (but DSA keys are [not recommended](https://security.stackexchange.com/a/46781))
  - OpenSSH 7.0 and higher no longer accept DSA keys by default
  - Note tested on OTP 25+, but still expected to work

## Installation

The package can be installed by adding `:ssh_client_key_api` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ssh_client_key_api, "~> 0.2.0"}
  ]
end
```

## Using SSHClientKeyAPI

`SSHClientKeyAPI` is meant to primarily be used via the convenience function
`with_options/1`. See `with_options/1` for full list of available options.

```elixir
key = File.open!("path/to/id_rsa") # Other key types supported as well
known_hosts = File.open!("path/to/known_hosts", [:read, :write])

cb = SSHClientKeyAPI.with_options(
  identity: key,
  known_hosts: known_hosts,
  silently_accept_hosts: true
)
```

The result can then be passed as an option when creating an SSH connection.

Using `SSHKit.SSH.connect/2`:

```elixir
connection = SSHKit.SSH.connect("example.com", key_cb: cb)
```

Or through `SSHKit.context/2`:

```elixir
context = SSHKit.context("example.com", key_cb: cb)
```

## License

Copyright (c) 2017 Lab Zero Innovations Inc.

This library is MIT licensed. See the [LICENSE](https://github.com/labzero/ssh_client_key_api/blob/master/LICENSE) for details.
