# PQ verifier benchmark summary

_Generated 2026-07-06 19:57._

| Scheme | L2 gas | % gas cap | Steps | % step cap | Sig+PK felts | Fits caps |
|---|--:|--:|--:|--:|--:|:--:|
| ECDSA-STARK (baseline) | 30,855 | 0.0309% | 152 | 0.0152% | 3 | yes |
| Falcon-512 (FN-DSA) | 26,611,400 | 26.6114% | 239,795 | 23.9795% | 89 | yes |
| Falcon-512 direct (no hint) | 31,118,060 | 31.1181% | 284,834 | 28.4834% | 60 | yes |
| Falcon-512 SHAKE-256 (standard) | 63,965,138 | 63.9651% | 447,823 | 44.7823% | 89 | yes |
| Falcon-512 Poseidon (native) | 26,488,669 | 26.4887% | 237,462 | 23.7462% | 89 | yes |

## Pending implementation

- **ML-DSA-44 (Dilithium)** (lattice (module)) — Finalized; robust signing. Expected SHAKE-dominated cost in Cairo.
- **Poseidon-WOTS+ (hash-based)** (hash-based (non-standard)) — Cheapest Cairo compute; needs research-grade security analysis. Large signature.
