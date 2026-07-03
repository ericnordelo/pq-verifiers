# PQ verifier benchmark summary

_Generated 2026-07-03 11:30._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |
| Falcon-512 (FN-DSA) | 76,248,400 | 76.2484% | 668,947 | 66.8947% | 89 | yes |
| Falcon-512 direct (no hint) | 76,153,420 | 76.1534% | 667,762 | 66.7762% | 60 | yes |

## Pending implementation

- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
