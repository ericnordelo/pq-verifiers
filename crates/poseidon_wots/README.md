# Poseidon-WOTS+ verifier

**Scheme:** hash-based (WOTS+ / Merkle) instantiated with Poseidon, **non-standard**.
**Status:** stub (pending implementation).

A post-quantum candidate that verifies using only hashing, which is cheap on Starknet
(Poseidon is a native builtin). The trade-off: it is not a recognized standard, its signature
is large, and its security at this field size needs dedicated analysis. The standardized,
SHA/SHAKE-based analog is SLH-DSA (SPHINCS+).

Implements `PqSignatureVerifier`. Reference:
[NIST FIPS 205 (SLH-DSA)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf).

## Current efficiency

No measurements yet: the crate is a stub, so it has no ratchet entries.
