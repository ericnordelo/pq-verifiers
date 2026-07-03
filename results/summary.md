# PQ verifier benchmark summary

_Generated 2026-07-03 13:40._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |
| Falcon-512 (FN-DSA) | 76,251,800 | 76.2518% | 668,981 | 66.8981% | 89 | yes |
| Falcon-512 direct (no hint) | 76,153,920 | 76.1539% | 667,767 | 66.7767% | 60 | yes |
| Falcon-512 Poseidon (hint) | 75,810,314 | 75.8103% | 665,745 | 66.5745% | 89 | yes |
| Falcon-512 Poseidon direct | 75,712,434 | 75.7124% | 664,530 | 66.453% | 60 | yes |

## Pending implementation

- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
