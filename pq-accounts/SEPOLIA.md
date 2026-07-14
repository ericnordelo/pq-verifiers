# Deploying to Sepolia (and mainnet)

The [devnet quickstart](USAGE.md#quickstart-devnet) does everything in one command. On a
public network the same CLI runs each step explicitly: declare the class, fund the
account's address, deploy, then transact — from the terminal or from a browser dapp like
Voyager. Everything below is Sepolia; mainnet is identical with a mainnet RPC and real
funds (see [Mainnet](#mainnet)).

> **Never use the committed demo key on a public network** — its private material is
> public. Generate your own key (step 1).

This assumes the one-time setup and the `pq-accounts` alias from the
[quickstart](USAGE.md#quickstart-devnet): the toolchain, the `.venv`, and the built
contracts and CLI.

## 1. Environment

Point the environment at Sepolia, your own key, and a funder. Any Starknet JSON-RPC 0.8+
endpoint works (a public one is shown; Alchemy, Infura, and Nethermind also serve
Sepolia):

```bash
export PQ_RPC=https://api.zan.top/public/starknet-sepolia/rpc/v0_10
export PQ_FALCON_PY=/path/to/falcon.py
export PQ_PYTHON=$PWD/.venv/bin/python3
export PQ_FALCON_KEY=$PWD/my-falcon-key.json
# A funded account of yours pays the one-time class declaration. Use a single-signer
# account whose private key Starknet.js can sign with (e.g. Ready/ArgentX).
export PQ_FUNDER_ADDRESS=0xYOUR_ACCOUNT
export PQ_FUNDER_PRIVATE_KEY=0xITS_KEY
```

Generate your own Falcon key if you don't have one yet:

```bash
"$PQ_PYTHON" signers/falcon-python/falcon_signer.py keygen \
  --falcon-py "$PQ_FALCON_PY" --key my-falcon-key.json
```

## 2. Declare, prefund, deploy

```bash
# 1. Declare the account class (one-time per class; idempotent). Prints the class hash.
pq-accounts declare --scheme falcon-512-shake

# 2. Derive the account address from your key, then send it ~2 STRK before deploying
#    (from your wallet, or https://faucet.starknet.io).
pq-accounts constructor-calldata --scheme falcon-512-shake \
  --class-hash 0xCLASS_HASH --salt 0x0

# 3. Deploy — the account Falcon-verifies its own deployment signature on-chain.
pq-accounts deploy-account --scheme falcon-512-shake \
  --class-hash 0xCLASS_HASH --address-salt 0x0
pq-accounts status --address 0xYOUR_ACCOUNT
```

The account is now live at `https://sepolia.voyager.online/contract/0xYOUR_ACCOUNT`. Any
scheme from the [reference table](USAGE.md#scheme-reference) works; `ecdsa-stark` uses
`--private-key 0x...` (or `PQ_PRIVATE_KEY`) instead of the `PQ_FALCON_*` variables.

## 3. Transact from the CLI

Exactly as on devnet, now against Sepolia:

```bash
pq-accounts execute --scheme falcon-512-shake --account 0xYOUR_ACCOUNT \
  --to 0xTARGET --entrypoint transfer --calldata 0xRECIPIENT 0x1 0x0
pq-accounts status --address 0xYOUR_ACCOUNT
```

Falcon validation consumes meaningful L2 gas, so expect real STRK fees. Use the CLI's
live receipt output with the network's current gas price; [What transactions
cost](USAGE.md#what-transactions-cost) explains the receipt meter and lists
devnet-measured values per scheme.

## 4. Transact from a browser dapp (Voyager)

`pq-accounts serve` runs a local wallet daemon that exposes the deployed account to
browser dapps: it prints a paste-ready snippet that injects a `window.starknet_<id>`
wallet object into the page, the dapp's connect dialog lists it, and no dapp-side
integration is needed. The snippet is a relay — signing happens in this process with your
key file, the key never enters the browser, and requests are token-gated per run. (On a
devnet the daemon also works, but only with a dapp you serve locally, not with Voyager,
which indexes public networks only.)

Voyager's connect dialog is StarknetKit, which only shows an injected wallet whose id
matches one of the connectors it registers. The daemon therefore injects under a
registered-but-absent slot (default `braavos`, shown as "Install Braavos" until injected)
— StarknetKit still displays this wallet's own name (e.g. "PQ Falcon-512 SHAKE-256") and
icon, just in that slot. Pick another slot with `--wallet-id` (e.g. `keplr`, `okxwallet`)
if you have Braavos installed. Dapps that use get-starknet directly accept any id.

```bash
export PQ_ACCOUNT=0xYOUR_DEPLOYED_ACCOUNT
pq-accounts serve --scheme falcon-512-shake
```

Then, in the dapp's tab: open the DevTools console, paste the snippet the daemon printed,
and click the dapp's connect-wallet button — select the "PQ ..." wallet named after your
scheme. Contract writes arrive as `wallet_addInvokeTransaction` and are Falcon-signed and
submitted by the daemon; sign-message flows arrive as `wallet_signTypedData` and verify
against the account's `is_valid_signature`.

If the connect button spins forever, watch the daemon log. A common cause is the dapp
requesting a network switch (`wallet_switchStarknetChain`) to a different chain than
`PQ_RPC` — Voyager's wallet target is set independently of the subdomain, so it may ask
for mainnet on the Sepolia site. The daemon accepts the switch and prints a warning;
transactions still go to `PQ_RPC`'s network. Set the dapp's own network selector to match
`PQ_RPC` so what it displays lines up with where transactions land.

## Mainnet

The same steps target mainnet: point `PQ_RPC` at a mainnet JSON-RPC endpoint, fund the
funder and the account with real STRK, and use a key you actually protect. Declare,
deploy, execute, and the browser flow are all identical. Fees scale with the network's L2
gas price, so each Falcon transaction costs real money — the [cost
figures](USAGE.md#what-transactions-cost) are the gas to price against it.
