# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA), lattice-based (NTRU), draft NIST standard (FIPS 206).
Five verifier variants across three hash-to-point backends: non-standard BLAKE2s (hint and
direct), standard SHAKE-256 (hint and direct), and non-standard native-Poseidon (hint).
**Status:** measured.

A post-quantum candidate with the smallest signatures and keys of the lattice schemes, and
the only one already demonstrated in a live Starknet wallet. Verification is integer-only
and runs fully on-chain: a hash-to-point binds the message, the product `s1*h` over
q = 12289 is obtained in two 512-point transforms on the shared lazy-reduction NTT engine
([`ntt`](../ntt)), and a centered norm bound decides acceptance. Five registered variants
share the NTT-domain public key:
**hint** (`falcon_512`: BLAKE2s hash-to-point via the `core::blake` builtin; 2 forward NTTs
check a signer-supplied `s1*h`, +29 signature felts),
**direct** (`falcon_512_direct`: BLAKE2s hash-to-point; `INTT(NTT(s1) ∘ h_ntt)`, 31-felt
signature, no hint),
**SHAKE-256** (`falcon_512_shake`: the standard hash-to-point in pure Cairo, same hint
check as `falcon_512`),
**SHAKE-256 direct** (`falcon_512_shake_direct`: the standard hash-to-point with the
hint-free direct core, 31-felt signature), and
**Poseidon** (`falcon_512_poseidon`: a native `hades_permutation` squeeze, same hint check).
The three hint variants differ only in the hash-to-point. BLAKE2s and Poseidon are cheap and
message-binding but non-standard (each needs a matching signer); Poseidon — the cheapest
variant — is built on native field arithmetic and therefore also the most
STARK-proving-friendly. SHAKE-256 is interoperable with any standards-compliant Falcon
signer; its pure-Cairo Keccak-f[1600] (flat unrolled rounds over u128 lanes, lazy block
squeezing — see `src/hashing/shake256.cairo`) dominates that variant's cost at roughly 2.4×
the non-standard ones, while staying within both validation caps, so even the
standards-compliant variant is deployable (a `keccak_f1600` syscall, SNIP-32, would close
the remaining gap). `falcon_512_shake_direct` pairs that standard hash-to-point with the
hint-free direct core: no signer-supplied product and the smallest input trust surface,
mirroring a bare FIPS signature most closely, at the highest cost of the five (still within
both caps). Packed inputs are validated canonical on unpack, and the verifier
consumes the NTT engine's unreduced transforms, folding reduction into its pointwise
divisibility check. The bench fixtures are genuine signatures from the reference falcon.py
sampler (`scripts/gen_falcon_fixture.py`, `--variant shake` / `--variant poseidon`);
tampered variants are rejected in tests.

Implements `PqSignatureVerifier`.
References: [Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[s2morrow reference verifier](https://github.com/feltroidprime/s2morrow) ·
[falcon.py](https://github.com/tprest/falcon.py).

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| verify, hint variant (BLAKE2s) | 26,611,400 | 239,795 |
| verify, direct variant (BLAKE2s) | 31,118,060 | 284,834 |
| verify, Poseidon variant (native) | 26,488,669 | 237,462 |
| verify, SHAKE-256 variant (standard) | 63,965,138 | 447,823 |
| verify, SHAKE-256 direct variant (standard) | 68,471,798 | 492,859 |
