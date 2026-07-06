# Benchmark accounts

**Component:** the account harness for the in-`__validate__` scenario: one deployable
account contract per verifier.
**Status:** measured (ECDSA-STARK and the four Falcon-512 variants); other PQ verifiers'
accounts land as their schemes are implemented.

Unlike the verifier crates (one scheme each), this crate collects **one account contract
per verifier**, each in its own module. An account wraps its scheme the way a Starknet
account would: `validate()` reads the transaction hash and signature from the transaction
info, loads the stored public key, and runs the scheme's `verify`. Measuring a
deploy-and-call of it (minus a deploy-only baseline) captures the realistic validation
cost (dispatch, signature deserialization, and the key's storage read) on top of bare
verification, and building the contracts yields each scheme's contract-class size.

All accounts expose the same `IValidateBench` interface, defined at the crate root.

```
src/
  lib.cairo          # IValidateBench + one module per verifier account
  ecdsa_stark.cairo  # EcdsaStarkAccount (classical control)
  falcon_512.cairo   # Falcon512Account (hint) + Falcon512DirectAccount (direct)
                     #   + Falcon512ShakeAccount (SHAKE-256) + Falcon512PoseidonAccount
```

## Current efficiency

One row per verifier account. The 100M-L2-gas / 1M-step validation cap is the deployability
threshold, and every account fits it: the BLAKE2s, direct, and Poseidon Falcon accounts with
wide margin, and `Falcon512ShakeAccount` — whose pure-Cairo SHAKE-256 hash-to-point dominates
its cost — at about two-thirds of the gas cap and under half the step cap.

| Account | Measurement | L2 gas | Steps |
|---|---|--:|--:|
| `EcdsaStarkAccount` | inside `__validate__` | 160,795 | 1,437 |
| `Falcon512Account` (hint) | inside `__validate__` | 28,181,860 | 254,065 |
| `Falcon512DirectAccount` (direct) | inside `__validate__` | 32,637,610 | 298,618 |
| `Falcon512PoseidonAccount` (Poseidon) | inside `__validate__` | 28,059,129 | 251,731 |
| `Falcon512ShakeAccount` (SHAKE-256) | inside `__validate__` | 65,535,198 | 462,088 |
