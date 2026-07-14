# Falcon Python Signer

This signer lets `pq-accounts/cli` use the Falcon account contracts without
reimplementing Falcon signing in TypeScript. It wraps a local checkout of
`github.com/tprest/falcon.py`, derives the packed public key expected by the Cairo
accounts, and signs Starknet transaction hashes with the hash-to-point construction of
the requested scheme, each mirroring its on-chain counterpart in `crates/falcon_512`:
BLAKE2s for `falcon-512` and `falcon-512-direct`, the standard SHAKE-256 of the Falcon
specification for `falcon-512-shake` and `falcon-512-shake-direct`, and the native-Poseidon
squeeze for `falcon-512-poseidon` (verified against the `core::poseidon` known-answer vector
before every use). Before returning a signature it re-checks the exact on-chain acceptance
condition (verification equation and centered norm bound).

The signer is intended for local experimentation with the account contracts. The key file
contains private signing material encoded as a Python pickle inside JSON; keep it local
and do not treat it as a production wallet format.

`demo-key.json` is a committed key used by the CLI quickstart so testers can skip
keygen. Its private material is public in the repository — devnet only, never hold real
funds with it.

## Setup

Clone and prepare `falcon.py` separately:

```bash
git clone https://github.com/tprest/falcon.py /path/to/falcon.py
git -C /path/to/falcon.py checkout 5145a818c9512b4a443507d3375e75dae3076af6
python3 -m venv pq-accounts/.venv
pq-accounts/.venv/bin/pip install numpy pycryptodome beartype
```

The CLI invokes this signer with the interpreter named by `PQ_PYTHON`; point it at
`pq-accounts/.venv/bin/python3` so the dependencies stay local to the project.

Generate a key file:

```bash
pq-accounts/.venv/bin/python3 pq-accounts/signers/falcon-python/falcon_signer.py keygen \
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

One key file serves every Falcon variant — the keypair is hash-to-point agnostic, and
the signer selects the construction from the scheme key in each request. It returns the
60-felt hint signature for `falcon-512`, `falcon-512-shake`, and `falcon-512-poseidon`,
and the 31-felt `s1 || salt` prefix for `falcon-512-direct` and `falcon-512-shake-direct`.

## JSON Protocol

In protocol mode, the signer reads one request from stdin and writes one JSON object to
stdout. The CLI sends `public-key`, `sign-hash`, `sign-transaction`, or
`sign-deploy-account`; transaction requests include a `payload.hash` computed by
Starknet.js.
