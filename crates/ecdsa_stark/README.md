# ECDSA-STARK verifier

**Scheme:** ECDSA over the STARK curve — classical elliptic-curve, **not** post-quantum.
**Status:** measured (reference baseline).

This is the signature scheme Starknet accounts use today. It is included only as a familiar
cost reference to compare the post-quantum candidates against — it is **not** a PQ offering
(a quantum computer running Shor's algorithm would break it).

Implements `PqSignatureVerifier`. Verification is `core::ecdsa::check_ecdsa_signature`.
