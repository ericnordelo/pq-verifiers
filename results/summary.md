# PQ verifier benchmark summary

_Generated 2026-07-03 14:35._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |
| Falcon-512 (FN-DSA) | 35,643,340 | 35.6433% | 322,958 | 32.2958% | 89 | yes |
| Falcon-512 direct (no hint) | 37,190,480 | 37.1905% | 340,697 | 34.0697% | 60 | yes |

## Pending implementation

- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
