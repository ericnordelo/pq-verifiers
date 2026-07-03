# Benchmark accounts

**Component:** the account harness for the in-`__validate__` scenario — one deployable
account contract per verifier.
**Status:** measured (ECDSA-STARK); the PQ verifiers' accounts land as their schemes are
implemented.

Unlike the verifier crates (one scheme each), this crate collects **one account contract
per verifier**, each in its own module. An account wraps its scheme the way a Starknet
account would: `validate()` reads the transaction hash and signature from the transaction
info, loads the stored public key, and runs the scheme's `verify`. Measuring a
deploy-and-call of it (minus a deploy-only baseline) captures the realistic validation
cost — dispatch, signature deserialization, and a storage read — on top of bare
verification, and building the contracts yields each scheme's contract-class size.

All accounts expose the same `IValidateBench` interface, defined at the crate root.

```
src/
  lib.cairo          # IValidateBench + one module per verifier account
  ecdsa_stark.cairo  # EcdsaStarkAccount (classical control)
```

## Current efficiency

One row per verifier account:

| Account | Measurement | L2 gas | Steps |
|---|---|--:|--:|
| `EcdsaStarkAccount` | inside `__validate__` | 160,795 | 1,437 |
