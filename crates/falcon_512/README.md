# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA) — lattice-based (NTRU), draft NIST standard (FIPS 206),
with the hash-to-point XOF swapped from SHAKE-256 to BLAKE2s (non-standard).
**Status:** measured.

A post-quantum candidate with the smallest signatures and keys of the lattice schemes, and
the only one already demonstrated in a live Starknet wallet. Verification is integer-only
and runs fully on-chain: a BLAKE2s hash-to-point binds the message (`core::blake` builtin),
the product `s1*h` over q = 12289 is obtained in two 512-point transforms on the shared
lazy-reduction NTT engine ([`ntt`](../ntt)), and a centered norm bound decides acceptance.
Two registered variants share the NTT-domain public key:
**hint** (`falcon_512`: 2 forward NTTs check a signer-supplied `s1*h`, +29 signature felts)
and **direct** (`falcon_512_direct`: `INTT(NTT(s1) ∘ h_ntt)`, 31-felt signature, no hint).
Packed inputs are validated canonical on unpack. The bench fixture is a genuine signature
from the reference falcon.py sampler (`scripts/gen_falcon_fixture.py`); tampered variants
are rejected in tests.

Implements `PqSignatureVerifier`. Port provenance and decisions: [`PORTING.md`](PORTING.md).
References: [Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[s2morrow reference verifier](https://github.com/feltroidprime/s2morrow) ·
[falcon.py](https://github.com/tprest/falcon.py).

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| verify, hint variant | 35,643,340 | 322,958 |
| verify, direct variant | 37,190,480 | 340,697 |
