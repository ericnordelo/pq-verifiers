# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA) — lattice (NTRU), NIST Category 1, draft FIPS 206.
**Status:** measured.

Compact lattice signature with the smallest key/signature of the PQ candidates, making it an
attractive account-signer — but its verification is heavy on-chain. This is the direct-NTT
variant (no signer-supplied hint): recover `s1 = msg_point - s2*h` (mod q, via the NTT) and
check the integer norm bound. The SHAKE-256 hash-to-point is computed off-chain and its result
is carried in the signature (the s2morrow interop path). The looped NTT is ported from
s2morrow (MIT); a real fn-dsa signature is verified (and a tampered one rejected) in the tests.

Measured verify cost is ~125.8M L2 gas — **over** the 100M validate budget; a production
account would need the cheaper unrolled or hint-based NTT (smaller gas, but a larger/harder-to-
audit trusted base). See `PORTING.md`.

Implements `PqSignatureVerifier`. Reference: [FIPS 206 (draft)](https://csrc.nist.gov/pubs/fips/206/ipd), [Falcon](https://falcon-sign.info/).
