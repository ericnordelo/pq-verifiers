# ECDSA-STARK verifier

**Scheme:** ECDSA over the STARK curve, classical elliptic-curve, **not** post-quantum.
**Status:** measured (reference baseline).

This is the signature scheme Starknet accounts use today. It is included only as a familiar
cost reference to compare the post-quantum candidates against. It is **not** a PQ offering
(a quantum computer running Shor's algorithm would break it). Verification delegates to
`core::ecdsa::check_ecdsa_signature`.

Implements `PqSignatureVerifier`. The in-`__validate__` scenario for this scheme is
measured by the account mock in [`bench_targets`](../bench_targets).

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| verify | 30,855 | 152 |
