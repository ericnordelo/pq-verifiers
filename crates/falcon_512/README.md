# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA) — lattice-based (NTRU), draft NIST standard (FIPS 206).
Three verifier variants: a non-standard BLAKE2s hash-to-point (hint and direct) and the
standard SHAKE-256 hash-to-point (hint).
**Status:** measured.

A post-quantum candidate with the smallest signatures and keys of the lattice schemes, and
the only one already demonstrated in a live Starknet wallet. Verification is integer-only
and runs fully on-chain: a hash-to-point binds the message, the product `s1*h` over
q = 12289 is obtained in two 512-point transforms on the shared lazy-reduction NTT engine
([`ntt`](../ntt)), and a centered norm bound decides acceptance. Three registered variants
share the NTT-domain public key:
**hint** (`falcon_512`: BLAKE2s hash-to-point via the `core::blake` builtin; 2 forward NTTs
check a signer-supplied `s1*h`, +29 signature felts),
**direct** (`falcon_512_direct`: BLAKE2s hash-to-point; `INTT(NTT(s1) ∘ h_ntt)`, 31-felt
signature, no hint), and
**SHAKE-256** (`falcon_512_shake`: the standard hash-to-point in pure Cairo, same hint
check as `falcon_512`). BLAKE2s is cheap but requires a matching custom signer; SHAKE-256 is
interoperable with any standards-compliant Falcon signer but its pure-Cairo Keccak-f[1600]
dominates cost and pushes verification past the validation step cap, so that variant is a
benchmark target rather than a deployable account (a `keccak_f1600` syscall, SNIP-32, would
close the gap). Packed inputs are validated canonical on unpack. The bench fixtures are
genuine signatures from the reference falcon.py sampler
(`scripts/gen_falcon_fixture.py [--variant shake]`); tampered variants are rejected in tests.

Implements `PqSignatureVerifier`. Port provenance and decisions: [`PORTING.md`](PORTING.md).
References: [Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[s2morrow reference verifier](https://github.com/feltroidprime/s2morrow) ·
[falcon.py](https://github.com/tprest/falcon.py).

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| verify, hint variant (BLAKE2s) | 35,643,340 | 322,958 |
| verify, direct variant (BLAKE2s) | 37,190,480 | 340,697 |
| verify, SHAKE-256 variant (standard) | 202,528,285 | 1,613,066 |
