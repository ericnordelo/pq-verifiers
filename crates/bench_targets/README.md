# Benchmark targets

**Component:** account mock contracts for the in-`__validate__` scenario.
**Status:** measured.

Deployable contracts that wrap a verifier the way a Starknet account would: `validate()`
reads the transaction hash and signature from the transaction info, loads the stored
public key, and runs the scheme's `verify`. Measuring a deploy-and-call of these (minus a
deploy-only baseline) captures the realistic validation cost — dispatch, signature
deserialization, and a storage read — on top of bare verification.

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| ECDSA-STARK inside `__validate__` | 160,795 | 1,437 |
