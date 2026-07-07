# pq-accounts

`pq-accounts` contains deployable Starknet account contracts that use the verifier
implementations in this repository, and three ways to drive them: a Starknet.js CLI, an
MCP server for LLM clients, and a local wallet daemon that plugs the accounts into
browser dapps such as Voyager.

See [`USAGE.md`](USAGE.md) for the walkthrough — on a devnet, one command deploys and
transacts through an account: `node cli/dist/index.js quickstart`.

## Projects

- `contracts/`: Cairo account contracts. `src/accounts/` holds one account per verifier
  scheme (`EcdsaStarkAccount`, `Falcon512Account`, `Falcon512DirectAccount`,
  `Falcon512ShakeAccount`, `Falcon512PoseidonAccount`), each implementing the account
  entrypoints used by Starknet (`__execute__`, `__validate__`, `__validate_declare__`,
  `__validate_deploy__`, `is_valid_signature`, `supports_interface`); `src/utils/` holds
  the shared account interfaces, the execution/validation helpers, and the reusable
  verifier-generic account component (`PqAccountComponent`) that the Falcon accounts
  embed — a concrete account is the component instantiated with its verifier.
- `cli/`: TypeScript command line tool plus a stdio MCP server (`dist/mcp.js`) for LLM
  clients. Both use Starknet.js for transaction assembly, fee estimation, nonce handling,
  and RPC submission, while scheme adapters provide the signature felts consumed by the
  account contracts.
- `signers/`: External signer processes used by the CLI for schemes whose signing logic
  is not implemented in TypeScript. The Falcon signer wraps a local `falcon.py` checkout
  and returns the exact felt layouts expected by the Falcon accounts, deriving the
  message point with the hash-to-point construction of the requested scheme (BLAKE2s,
  standard SHAKE-256, or Poseidon) — one key file serves every Falcon variant.

The benchmark accounts under `crates/bench_targets` remain measurement harnesses. The
contracts here are the accounts intended for on-chain interaction.
