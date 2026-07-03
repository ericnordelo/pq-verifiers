# pq-accounts

`pq-accounts` contains deployable Starknet account contracts that use the verifier
implementations in this repository, plus a small Starknet.js-based CLI for deploying and
sending transactions through those accounts.

## Projects

- `contracts/`: Cairo account contracts. Each account lives in its own source file and
  implements the account entrypoints used by Starknet: `__execute__`, `__validate__`,
  `__validate_declare__`, `__validate_deploy__`, `is_valid_signature`, and
  `supports_interface`.
- `cli/`: TypeScript command line tool. It uses Starknet.js for transaction assembly,
  fee estimation, nonce handling, and RPC submission, while scheme adapters provide the
  signature felts consumed by the account contracts.
- `signers/`: External signer processes used by the CLI for schemes whose signing logic
  is not implemented in TypeScript. The Falcon signer wraps a local `falcon.py` checkout
  and returns the exact felt layouts expected by the Falcon accounts.

The benchmark accounts under `crates/bench_targets` remain measurement harnesses. The
contracts here are the accounts intended for on-chain interaction.
