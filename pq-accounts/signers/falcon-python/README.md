# Falcon Python Signer

This signer lets `pq-accounts/cli` use the Falcon account contracts without
reimplementing Falcon signing in TypeScript. It wraps a local checkout of
`github.com/tprest/falcon.py`, derives the packed public key expected by the Cairo
accounts, and signs Starknet transaction hashes with the same BLAKE2s hash-to-point
construction used by `crates/falcon_512`.

The signer is intended for local experimentation with the account contracts. The key file
contains private signing material encoded as a Python pickle inside JSON; keep it local
and do not treat it as a production wallet format.

## Setup

Clone and prepare `falcon.py` separately:

```bash
git clone https://github.com/tprest/falcon.py /path/to/falcon.py
python3 -m pip install numpy pycryptodome beartype
```

Generate a key file:

```bash
python3 pq-accounts/signers/falcon-python/falcon_signer.py keygen \
  --falcon-py /path/to/falcon.py \
  --key pq-accounts/signers/falcon-python/falcon-key.json
```

Print constructor calldata for the hint account:

```bash
node pq-accounts/cli/dist/index.js constructor-calldata \
  --scheme falcon-512 \
  --signer-command python3 \
  --signer-arg pq-accounts/signers/falcon-python/falcon_signer.py \
  --signer-arg --falcon-py \
  --signer-arg /path/to/falcon.py \
  --signer-arg --key \
  --signer-arg pq-accounts/signers/falcon-python/falcon-key.json
```

Use `--scheme falcon-512-direct` with the same key file for the direct account. The
signer returns the 60-felt hint signature for `falcon-512` and the 31-felt `s1 || salt`
prefix for `falcon-512-direct`.

## JSON Protocol

In protocol mode, the signer reads one request from stdin and writes one JSON object to
stdout. The CLI sends `public-key`, `sign-hash`, `sign-transaction`, or
`sign-deploy-account`; transaction requests include a `payload.hash` computed by
Starknet.js.
