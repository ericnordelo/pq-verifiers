# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA), lattice-based (NTRU), draft NIST standard (FIPS 206).
Five verifier variants across three hash-to-point backends: non-standard BLAKE2s (hint and
direct), standard SHAKE-256 (hint and direct), and non-standard native-Poseidon (hint).
**Status:** measured.

A post-quantum candidate with the smallest signatures and keys of the lattice schemes, and
the only one already demonstrated in a live Starknet wallet. Verification is integer-only
and runs fully on-chain: a hash-to-point binds the message, the product `s1*h` over
q = 12289 is checked or computed with the shared [`ntt`](../ntt) crate, and a centered norm
bound decides acceptance. Canonical base-Q packing is validated while decoding directly to
the verifier's `u16` representation. The hint core uses two generated, fully unrolled
Falcon-512 forward transforms and a fused pointwise-check/norm pass; the direct core uses one
generated forward transform and the generic inverse engine. Five registered variants share
the NTT-domain public key:
**hint** (`falcon_512`: BLAKE2s hash-to-point via the `core::blake` builtin; two forward NTTs
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
squeezing — see `src/hashing/shake256.cairo`) dominates that variant's cost. The SHAKE hint
verifier uses about 4.2× the gas and 3.2× the steps of the native-Poseidon verifier, while
staying within both validation caps, so even the standards-compliant variant is deployable
(a `keccak_f1600` syscall, SNIP-32, would close the remaining gap).
`falcon_512_shake_direct` pairs that standard hash-to-point with the
hint-free direct core: no signer-supplied product and the smallest input trust surface,
mirroring a bare FIPS signature most closely, at the highest cost of the five (still within
both caps). Generated forward-transform outputs are reduced once after their straight-line
butterfly graph; the generic engine remains the direct variant's inverse path and the
generated path's correctness oracle. The bench fixtures are genuine signatures from the
reference falcon.py sampler (`scripts/gen_falcon_fixture.py`, `--variant shake` /
`--variant poseidon`); tampered variants are rejected in tests.

The hint/direct distinction (how `s1*h` is obtained, and what it does and does not
affect) is explained in [`HINT_VS_DIRECT.md`](HINT_VS_DIRECT.md).

Implements `PqSignatureVerifier`.
References: [Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[s2morrow reference verifier](https://github.com/feltroidprime/s2morrow) ·
[falcon.py](https://github.com/tprest/falcon.py).

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| verify, hint variant (BLAKE2s) | 12,809,640 | 104,854 |
| verify, direct variant (BLAKE2s) | 23,005,760 | 205,781 |
| verify, Poseidon variant (native) | 12,045,449 | 97,681 |
| verify, SHAKE-256 variant (standard) | 50,163,668 | 312,892 |
| verify, SHAKE-256 direct variant (standard) | 60,359,788 | 413,819 |
