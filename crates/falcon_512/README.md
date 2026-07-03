# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA) — lattice-based (NTRU), draft NIST standard (FIPS 206),
with the hash-to-point XOF swapped from SHAKE-256 to BLAKE2s (non-standard).
**Status:** measured.

A post-quantum candidate with the smallest signatures and keys of the lattice schemes, and
the only one already demonstrated in a live Starknet wallet. Verification is integer-only
and runs fully on-chain: a hash-to-point binds the message, the product `s1*h` over
q = 12289 is obtained in two 512-point transforms, and a centered norm bound decides
acceptance. Four registered schemes share the NTT-domain public key — two verify variants,
**hint** (2 forward NTTs check a signer-supplied `s1*h`, 60-felt signature) and **direct**
(`INTT(NTT(s1) ∘ h_ntt)`, 31-felt signature, no hint), each with two hash-to-point
constructions: **BLAKE2s** counter-mode XOF with spec rejection sampling (`falcon_512`,
`falcon_512_direct`) and **Poseidon** sponge squeeze as deployed by s2morrow
(`falcon_512_poseidon`, `falcon_512_poseidon_direct`; biased mod-Q extraction — upstream's
Rényi bound of ≤0.37 bits is attributed, its reference unpublished). Packed inputs are
validated canonical on unpack. Each construction's bench fixture is a genuine signature
from the reference falcon.py sampler (`scripts/gen_falcon_fixture.py`); tampered variants
are rejected in tests.

Implements `PqSignatureVerifier`. Port provenance and decisions: [`PORTING.md`](PORTING.md).
References: [Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[s2morrow reference verifier](https://github.com/feltroidprime/s2morrow) ·
[falcon.py](https://github.com/tprest/falcon.py).
