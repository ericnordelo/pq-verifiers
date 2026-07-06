# ML-DSA-44 verifier

**Scheme:** ML-DSA-44 (CRYSTALS-Dilithium), lattice-based (module), final NIST standard
(FIPS 204).
**Status:** stub (pending implementation).

A fully standardized post-quantum candidate. Its signing is integer-only, avoiding the
high-precision floating point Falcon needs. On-chain verification combines an NTT over
q = 8380417 with heavy SHAKE-256 hashing; in Cairo the hashing is expected to dominate the
cost.

Implements `PqSignatureVerifier`. Reference:
[NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).

## Current efficiency

No measurements yet: the crate is a stub, so it has no ratchet entries.
