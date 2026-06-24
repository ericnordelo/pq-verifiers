# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA) — lattice-based (NTRU), draft NIST standard (FIPS 206).
**Status:** stub (pending implementation).

A post-quantum candidate with the smallest signatures and keys of the lattice schemes, and
the only one already demonstrated in a live Starknet wallet. On-chain verification is
integer-only (an NTT over q = 12289 plus a norm check), with the message hashed to a point
via SHAKE-256.

Implements `PqSignatureVerifier`. Implementation plan: [`PORTING.md`](PORTING.md). References:
[Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[s2morrow reference verifier](https://github.com/feltroidprime/s2morrow).
