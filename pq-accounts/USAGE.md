# Deploying and transacting with the accounts

A step-by-step walkthrough for deploying the `pq-accounts` account contracts and sending
transactions through them, using the CLI in [`cli/`](cli) and the Falcon signer in
[`signers/falcon-python`](signers/falcon-python).

> Keep this guide in sync with the code. Whenever the account contracts
> ([`contracts/`](contracts)), the CLI ([`cli/`](cli)), or a signer ([`signers/`](signers))
> change, re-check every command and layout reference here and update as needed.

Paths below are relative to this `pq-accounts/` directory.

## What's here

- `contracts/` — the deployable account contracts. `contracts/src/accounts/` holds one
  account per verifier scheme (`EcdsaStarkAccount`, `Falcon512Account`,
  `Falcon512DirectAccount`, `Falcon512ShakeAccount`, `Falcon512PoseidonAccount`);
  `contracts/src/utils/` holds the shared account interfaces, the execution/validation
  helpers, and the verifier-generic `PqAccountComponent` the Falcon accounts embed.
- `cli/` — a Starknet.js command line tool (`accounts`, `public-key`,
  `constructor-calldata`, `sign-hash`, `deploy-account`, `execute`).
- `signers/falcon-python/` — an external Falcon signer wrapping `tprest/falcon.py`, which
  signs Starknet transaction hashes with the hash-to-point construction of the requested
  scheme: BLAKE2s (matching `crates/falcon_512`'s hint and direct variants), the standard
  SHAKE-256 of the Falcon specification, or the native-Poseidon squeeze.

The account descriptors the CLI exposes: `ecdsa-stark` (1 pubkey felt, `[r, s]`),
`falcon-512` (29 pubkey felts, 60 signature felts), `falcon-512-direct` (29 pubkey felts,
31 signature felts), `falcon-512-shake` and `falcon-512-poseidon` (29 pubkey felts, 60
signature felts each).

## One-time setup

1. Falcon signer dependencies:
   ```bash
   git clone https://github.com/tprest/falcon.py /path/to/falcon.py
   python3 -m pip install numpy pycryptodome beartype
   ```
2. Generate a Falcon key (one key file serves both Falcon variants):
   ```bash
   python3 signers/falcon-python/falcon_signer.py keygen \
     --falcon-py /path/to/falcon.py \
     --key signers/falcon-python/falcon-key.json
   ```
3. Build the account classes:
   ```bash
   (cd contracts && scarb build)
   ```
4. Build the CLI:
   ```bash
   (cd cli && npm install && npm run build)
   ```
5. Run a node. A local devnet is easiest (it provides funded, predeployed accounts used to
   declare classes and to prefund new accounts): `starknet-devnet --seed 0`.

For brevity the commands below use these shell definitions (run from `pq-accounts/`):

```bash
CLI="node cli/dist/index.js"
SIGNER=(--signer-command python3 \
  --signer-arg signers/falcon-python/falcon_signer.py \
  --signer-arg --falcon-py --signer-arg /path/to/falcon.py \
  --signer-arg --key --signer-arg signers/falcon-python/falcon-key.json)
RPC=http://127.0.0.1:5050/rpc
```

## Deploy and transact — `falcon-512` (hint variant)

1. **Declare the class.** The CLI has no declare command; use `sncast` (or Starknet.js)
   with a funded deployer — a devnet predeployed account works:
   ```bash
   sncast declare --contract-name Falcon512Account   # prints the class hash
   ```

2. **Inspect the constructor calldata / public key** (derived from your Falcon key; 29
   felts, length-prefixed):
   ```bash
   $CLI constructor-calldata --scheme falcon-512 "${SIGNER[@]}"
   ```

3. **Prefund the counterfactual address.** A `DEPLOY_ACCOUNT` transaction is paid for by
   the account being deployed, so its address must hold funds first. Starknet.js derives
   the address from the class hash, that constructor calldata, and the salt; mint or
   transfer funds to it (on devnet, use its mint endpoint or a predeployed account).

4. **Deploy the account** (omitting `--constructor-calldata` lets the CLI derive it from
   the signer):
   ```bash
   $CLI deploy-account \
     --rpc "$RPC" \
     --scheme falcon-512 "${SIGNER[@]}" \
     --class-hash 0xCLASS_HASH \
     --address-salt 0x0
   ```
   `__validate_deploy__` Falcon-verifies the deployment signature on-chain before the
   account is created.

5. **Send an invoke transaction** (Starknet.js `Account.execute`; the signer Falcon-signs
   the transaction hash the account reads from `tx_info.transaction_hash`):
   ```bash
   $CLI execute \
     --rpc "$RPC" \
     --scheme falcon-512 "${SIGNER[@]}" \
     --account 0xDEPLOYED_ACCOUNT \
     --to 0xTARGET --entrypoint transfer \
     --calldata 0xRECIPIENT 0x1 0x0
   ```

## The other Falcon variants

Identical flow with the variant's account contract and scheme key:

| Scheme key | Contract to declare | Signature | Hash-to-point |
|---|---|---|---|
| `falcon-512-direct` | `Falcon512DirectAccount` | 31 felts (`s1 \|\| salt`) | BLAKE2s |
| `falcon-512-shake` | `Falcon512ShakeAccount` | 60 felts (hint layout) | standard SHAKE-256 |
| `falcon-512-poseidon` | `Falcon512PoseidonAccount` | 60 felts (hint layout) | native Poseidon |

Declare the contract (`sncast declare --contract-name <Contract>`) and pass the scheme
key to `constructor-calldata`, `deploy-account`, and `execute`. The same key file serves
every variant: the Falcon keypair is hash-to-point agnostic, and the signer selects the
construction from the scheme key in each request.

## Handy checks

- **Sign a hash in isolation** (see the exact `tx_info.signature` felts, no deploy needed):
  ```bash
  $CLI sign-hash --scheme falcon-512 "${SIGNER[@]}" --hash 0xABC
  ```
- **List adapters** (account contract names, expected felt counts):
  ```bash
  $CLI accounts
  ```

## Notes

- `ecdsa-stark` needs no external signer — swap `"${SIGNER[@]}"` for
  `--private-key 0x...` and use `--scheme ecdsa-stark`.
- The signer key file holds private material as a pickle-in-JSON: local experimentation
  only, not a production wallet format.
- The CLI submits Starknet.js v10 v3 transactions; fee selection uses Starknet.js defaults.
- The benchmark accounts in `../crates/bench_targets` are measurement harnesses, not for
  on-chain interaction — these `pq-accounts` contracts are the deployable ones.
