# PQ verifier benchmark summary

_Generated 2026-07-06 18:15._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |
| Falcon-512 (FN-DSA) | 35,643,340 | 35.6433% | 322,958 | 32.2958% | 89 | yes |
| Falcon-512 direct (no hint) | 37,190,480 | 37.1905% | 340,697 | 34.0697% | 60 | yes |
| Falcon-512 SHAKE-256 (standard) | 202,528,285 | 202.5283% | 1,613,066 | 161.3066% | 89 | no |
| Falcon-512 Poseidon (native) | 36,885,049 | 36.885% | 334,374 | 33.4374% | 89 | yes |

## Pending implementation

- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
