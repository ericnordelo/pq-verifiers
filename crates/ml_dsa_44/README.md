# ML-DSA-44 verifier

**Scheme:** ML-DSA-44 (CRYSTALS-Dilithium) — lattice-based (module), final NIST standard
(FIPS 204).
**Status:** stub (pending implementation).

A post-quantum candidate that is fully standardized and has comparatively robust signing.
On-chain verification combines an NTT over q = 8380417 with heavy SHAKE-256 hashing; in
Cairo the hashing is expected to dominate the cost.

Implements `PqSignatureVerifier`. Reference:
[NIST FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).

## Current efficiency

No measurements yet: the crate is a stub, so it has no ratchet entries.
