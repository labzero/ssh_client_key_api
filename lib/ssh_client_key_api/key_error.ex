defmodule SSHClientKeyAPI.KeyError do
  defexception [:reason, :algorithm]

  def exception({reason, algo}), do: %__MODULE__{reason: reason, algorithm: algo}

  def exception(reason), do: %__MODULE__{reason: reason}

  def message(%__MODULE__{reason: :unsupported_algorithm}), do: "key algorithm is not supported"

  def message(%__MODULE__{reason: :passphrase_required}),
    do: "passphrase required for protected key"

  def message(%__MODULE__{reason: :incorrect_passphrase}),
    do: "passphrase invalid for protected key"

  def message(%__MODULE__{reason: :unsupported_algorithm, algorithm: algo}),
    do: "key algorithm is not supported: #{algo}"
end
