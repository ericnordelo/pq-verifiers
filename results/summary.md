# PQ verifier benchmark summary

_Generated 2026-06-24 13:48._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |

## Pending implementation

- **Falcon-512 (FN-DSA)** (lattice (NTRU)) — Smallest sig/key; demonstrated on Starknet (s2morrow). Fragile signing; Cat-1.
- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
