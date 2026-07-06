# pq-accounts CLI

`pq-accounts` is a Starknet.js-based command line tool for deploying and sending
transactions through the account contracts in `../contracts`. It keeps Starknet
transaction construction, fee estimation, nonce handling, and RPC submission inside
Starknet.js, while this package owns the scheme-specific signature adapter that matches
each account's `tx_info.signature` layout.

The built-in account descriptors are:

- `ecdsa-stark`: `EcdsaStarkAccount`, with one public-key felt and `[r, s]` signatures.
- `falcon-512`: `Falcon512Account`, with 29 public-key felts and 60 signature felts.
- `falcon-512-direct`: `Falcon512DirectAccount`, with 29 public-key felts and 31
  signature felts.
- `falcon-512-shake`: `Falcon512ShakeAccount`, with 29 public-key felts and 60 signature
  felts (standard SHAKE-256 hash-to-point).
- `falcon-512-poseidon`: `Falcon512PoseidonAccount`, with 29 public-key felts and 60
  signature felts (native-Poseidon hash-to-point).

ECDSA signing is implemented with Starknet.js. Falcon signing is delegated to an external
signer process so the CLI can interact with the accounts without reimplementing the
Falcon sampler in TypeScript.

## Install

```bash
cd pq-accounts/cli
npm install
npm run build
```

During development, run commands through `tsx`:

```bash
npm run dev -- accounts
```

After `npm run build`, the package exposes the `pq-accounts` binary from `dist/index.js`.

## Commands

List built-in signature adapters:

```bash
pq-accounts accounts
```

Derive the public key felts for a built-in signer:

```bash
pq-accounts public-key \
  --scheme ecdsa-stark \
  --private-key 0x1234
```

Sign a transaction hash directly. This is useful when testing an account's validation
logic in isolation:

```bash
pq-accounts sign-hash \
  --scheme ecdsa-stark \
  --private-key 0x1234 \
  --hash 0xabc
```

Inspect constructor calldata before deploying an account:

```bash
pq-accounts constructor-calldata \
  --scheme falcon-512 \
  --signer-command python3 \
  --signer-arg ../signers/falcon-python/falcon_signer.py \
  --signer-arg --falcon-py \
  --signer-arg /path/to/falcon.py \
  --signer-arg --key \
  --signer-arg ../signers/falcon-python/falcon-key.json
```

Send an invoke transaction from an account. The CLI uses Starknet.js `Account.execute`,
so the call shape should feel familiar to Starknet.js users:

```bash
pq-accounts execute \
  --rpc http://127.0.0.1:5050/rpc \
  --scheme ecdsa-stark \
  --private-key 0x1234 \
  --account 0xACCOUNT \
  --to 0xTARGET \
  --entrypoint transfer \
  --calldata 0xRECIPIENT 0x1 0x0
```

Deploy an account class with Starknet.js `Account.deployAccount`. If
`--constructor-calldata` is omitted, the CLI derives the public key from the selected
signer and encodes the constructor calldata expected by the selected account:

```bash
pq-accounts deploy-account \
  --rpc http://127.0.0.1:5050/rpc \
  --scheme ecdsa-stark \
  --private-key 0x1234 \
  --class-hash 0xCLASS_HASH \
  --address-salt 0x0
```

## External Signer Protocol

Use `--signer-command` for a verifier whose signature algorithm is not implemented in
this TypeScript package. Falcon accounts can use the signer in
`../signers/falcon-python`:

```bash
python3 ../signers/falcon-python/falcon_signer.py keygen \
  --falcon-py /path/to/falcon.py \
  --key ../signers/falcon-python/falcon-key.json
```

Then pass it to the CLI:

```bash
pq-accounts sign-hash \
  --scheme falcon-512 \
  --signer-command python3 \
  --signer-arg ../signers/falcon-python/falcon_signer.py \
  --signer-arg --falcon-py \
  --signer-arg /path/to/falcon.py \
  --signer-arg --key \
  --signer-arg ../signers/falcon-python/falcon-key.json \
  --hash 0xabc
```

The CLI writes one JSON request to the signer process on stdin:

```json
{
  "scheme": "falcon-512",
  "action": "sign-hash",
  "payload": {
    "hash": "0xabc"
  }
}
```

The signer must print JSON on stdout:

```json
{
  "signature": ["0x1", "0x2"]
}
```

For public-key derivation, the `action` is `public-key` and the signer should return a
`publicKey` array. For transaction submission, the `action` is `sign-transaction` or
`sign-deploy-account`. The payload includes `hash`, computed by Starknet.js from the
calls and signer details, so the external signer only has to sign the felt that the
account will read from `tx_info.transaction_hash`.

The package depends on Starknet.js v10 and submits v3 account transactions. Fee selection
uses Starknet.js defaults unless the command grows explicit v3 resource-bound flags.

## Adding a Scheme Adapter

Add a file under `src/schemes/` that implements `PqSignatureScheme`, then register it in
`src/schemes/registry.ts`. The adapter should document:

- the verifier crate it matches;
- the exact public-key felt layout;
- the exact signature felt layout;
- the accepted signer material;
- any preconditions needed by the on-chain verifier.

Adapters should return felt strings in the order consumed by the corresponding Cairo
`PqSignatureVerifier` implementation.

## Scope

The CLI targets the account contracts in `../contracts`. The benchmark contracts in
`../../crates/bench_targets` are measurement harnesses and are not used for on-chain
account interaction.
