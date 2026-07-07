# Deploying and transacting with the accounts

How to deploy the `pq-accounts` account contracts and send transactions through them,
from the CLI in [`cli/`](cli) or from an LLM through the MCP server.

> Keep this guide in sync with the code. Whenever the account contracts
> ([`contracts/`](contracts)), the CLI ([`cli/`](cli)), or a signer ([`signers/`](signers))
> change, re-check every command and layout reference here and update as needed.

Paths below are relative to this `pq-accounts/` directory.

## Quickstart (devnet)

One-time setup:

```bash
# Toolchain (pinned in ../.tool-versions): scarb + starknet-devnet, e.g. via asdf.
# Node >= 20, and Python 3.9+ for the Falcon signer.
git clone https://github.com/tprest/falcon.py /path/to/falcon.py
python3 -m pip install numpy pycryptodome beartype
(cd contracts && scarb build)
(cd cli && npm install && npm run build)
```

Run a devnet in a second terminal, then the quickstart:

```bash
starknet-devnet --seed 0
```

```bash
export PQ_FALCON_PY=/path/to/falcon.py
node cli/dist/index.js quickstart --scheme falcon-512-shake
```

The quickstart declares the scheme's account class (paid by a devnet predeployed
account), derives the account address from the signer's public key, mints 1000 STRK to
it, deploys the account — the deployment signature is Falcon-verified on-chain — and
sends 1 STRK back to the funder. It prints the transaction hashes plus the L2 gas and
fee each on-chain step consumed. Any scheme key from the reference table below works.

It signs with the committed demo key
([`signers/falcon-python/demo-key.json`](signers/falcon-python/demo-key.json)), whose
private material is public: devnet only. To use your own key, generate one and export it:

```bash
python3 signers/falcon-python/falcon_signer.py keygen \
  --falcon-py /path/to/falcon.py --key my-falcon-key.json
export PQ_FALCON_KEY=$PWD/my-falcon-key.json
```

Send further transactions from the deployed account:

```bash
export PQ_FALCON_KEY=${PQ_FALCON_KEY:-$PWD/signers/falcon-python/demo-key.json}
node cli/dist/index.js execute \
  --rpc http://127.0.0.1:5050/rpc --scheme falcon-512-shake \
  --account 0xACCOUNT --to 0xTARGET --entrypoint transfer \
  --calldata 0xRECIPIENT 0x1 0x0
node cli/dist/index.js status --rpc http://127.0.0.1:5050/rpc --address 0xACCOUNT
```

`ecdsa-stark` needs no Python signer: `--private-key 0x...` replaces the `PQ_FALCON_*`
variables (the quickstart generates a throwaway key by itself).

## From an LLM (MCP)

`cli/dist/mcp.js` is a stdio MCP server exposing the same operations as the CLI:
`list_schemes`, `account_status`, `declare`, `deploy_account`, `execute`, `sign_hash`,
`mint`, and `quickstart`. Register it in any MCP client, e.g. Claude Code:

```bash
claude mcp add pq-accounts \
  -e PQ_FALCON_PY=/path/to/falcon.py \
  -- node /absolute/path/to/pq-accounts/cli/dist/mcp.js
```

Then ask, for example:

- "Run the pq-accounts quickstart for falcon-512-shake and report the gas per step."
- "Deploy a falcon-512-poseidon account on my devnet."
- "Send 5 STRK from 0xACCOUNT to 0xRECIPIENT."
- "What is the status of account 0xACCOUNT?"

Configuration is environment-only:

| Variable | Meaning | Default |
|---|---|---|
| `PQ_RPC` | JSON-RPC endpoint | `http://127.0.0.1:5050/rpc` |
| `PQ_SCHEME` | default scheme key | `falcon-512-shake` |
| `PQ_FALCON_PY` | falcon.py checkout (required for Falcon schemes) | — |
| `PQ_FALCON_KEY` | Falcon key file | the committed demo key |
| `PQ_PRIVATE_KEY` | private key for `ecdsa-stark` | — |
| `PQ_FUNDER_ADDRESS` / `PQ_FUNDER_PRIVATE_KEY` | funded account for declarations | devnet predeployed account |
| `PQ_PYTHON` | python executable for the signer | `python3` |

The same variables configure the CLI (flags take precedence).

## Scheme reference

| Scheme key | Contract | Signature | Hash-to-point |
|---|---|---|---|
| `ecdsa-stark` | `EcdsaStarkAccount` | 2 felts (`[r, s]`) | — (classical control) |
| `falcon-512` | `Falcon512Account` | 60 felts (hint layout) | BLAKE2s |
| `falcon-512-direct` | `Falcon512DirectAccount` | 31 felts (`s1 \|\| salt`) | BLAKE2s |
| `falcon-512-shake` | `Falcon512ShakeAccount` | 60 felts (hint layout) | standard SHAKE-256 |
| `falcon-512-poseidon` | `Falcon512PoseidonAccount` | 60 felts (hint layout) | native Poseidon |

All Falcon accounts store a 29-felt packed public key. One key file serves every Falcon
variant: the keypair is hash-to-point agnostic, and the signer selects the construction
from the scheme key in each request.

## What transactions cost

The repository's benchmark tables price measured VM resources (steps, builtins) with the
official gas table, and that table — like the 100,000,000-gas validation budget — is
unchanged as of Starknet 0.14.3. Transaction **fees** are metered differently: for
Sierra >= 1.7 classes the receipt's L2 gas comes from the Sierra gas counter compiled
into the class, which runs roughly twice the resource-priced values on this workload.
Both meters are real; the first is the resource comparison between schemes, the second
is what you pay. All five accounts deploy and transact within the protocol's validation
budget on Starknet 0.14.3.

Receipt values measured on Starknet 0.14.3 (devnet, `quickstart` runs; the demo invoke
is a single STRK transfer — fee = L2 gas x the network L2 gas price, e.g. ~0.054 STRK
for the BLAKE2s invoke at devnet's 1 gwei-FRI price):

| Account | Invoke L2 gas | Deploy L2 gas |
|---|--:|--:|
| `ecdsa-stark` | 1,207,040 | 1,097,360 |
| `falcon-512` (BLAKE2s) | 54,424,000 | 68,480,800 |
| `falcon-512-direct` | 55,075,520 | 69,092,320 |
| `falcon-512-poseidon` | 56,464,000 | 70,560,800 |
| `falcon-512-shake` (standard) | 124,504,000 | 136,640,800 |

About 1.1M gas of every transaction is fixed protocol overhead (the `ecdsa-stark` rows
are nearly all overhead). The SHAKE values vary a few percent from one signature to the
next (its hash-to-point permutation count depends on the salt). The `quickstart` and the
MCP tools print these values from the live receipts of each run.

## Sepolia (advanced)

The quickstart is devnet-only; on a public network the same commands run individually.
**Never use the demo key outside a devnet** — its private material is public.

```bash
export PQ_FALCON_PY=/path/to/falcon.py PQ_FALCON_KEY=$PWD/my-falcon-key.json
RPC=https://YOUR_SEPOLIA_RPC

# 1. Declare, paid by your funded Sepolia account.
node cli/dist/index.js declare --rpc "$RPC" --scheme falcon-512-shake \
  --funder-address 0xYOUR_ACCOUNT --funder-private-key 0xYOUR_KEY

# 2. Derive the account address and prefund it with STRK (faucet or transfer).
node cli/dist/index.js constructor-calldata --scheme falcon-512-shake \
  --class-hash 0xCLASS_HASH --salt 0x0

# 3. Deploy, then transact.
node cli/dist/index.js deploy-account --rpc "$RPC" --scheme falcon-512-shake \
  --class-hash 0xCLASS_HASH --address-salt 0x0
node cli/dist/index.js execute --rpc "$RPC" --scheme falcon-512-shake \
  --account 0xACCOUNT --to 0xTARGET --entrypoint transfer --calldata 0xRECIPIENT 0x1 0x0
```

Falcon validation consumes tens of millions of L2 gas per transaction — expect real
STRK fees on public networks.

## Handy checks

- Sign a hash in isolation (the exact `tx_info.signature` felts, no deploy needed):
  ```bash
  node cli/dist/index.js sign-hash --scheme falcon-512-shake --hash 0xABC
  ```
- List adapters (account contract names, expected felt counts):
  ```bash
  node cli/dist/index.js accounts
  ```

## Notes

- The signer key file holds private material as a pickle-in-JSON: local experimentation
  only, not a production wallet format.
- The CLI submits Starknet.js v10 v3 transactions and estimates fees with validation
  enabled — a skip-validate estimate would under-provision gas for these
  validation-heavy accounts.
- A custom external signer can replace the bundled one via `--signer-command` /
  `--signer-arg`; the JSON protocol is documented in [`cli/README.md`](cli/README.md).
- The benchmark accounts in `../crates/bench_targets` are measurement harnesses, not for
  on-chain interaction — these `pq-accounts` contracts are the deployable ones.
