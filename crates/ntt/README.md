# NTT engine

**Component:** Number-Theoretic Transform (fast negacyclic polynomial multiplication),
shared by the lattice verifiers.
**Status:** measured.

A modular, scheme-agnostic NTT optimized for the Cairo cost model: butterfly arithmetic
runs natively in felt252 (one field multiplication and a few additions each, no per
operation reduction), and values are reduced in at most two u128 passes per transform.
Callers whose follow-up arithmetic tolerates a bounded unreduced output (a divisibility
check, a lazy-product INTT) can take the forward transform through `ntt_lazy`, which
skips the final reduction pass and reports the exact output bound instead.
Parameter sets plug in through `NttConfig` (modulus, root tables, permutation):
`falcon512` ships the production set (q = 12289, tprest/falcon.py interop order, same
convention as s2morrow); other schemes can add their own without touching the engine.

The safety argument for the delayed reduction (bound tracking, offsets, the 2^126
threshold) is documented in `src/engine.cairo` and kept executable by
`scripts/gen_ntt_tables.py`, which proves the engine equal to the recursive reference
on random and adversarial inputs and generates the derived tables (the felt252 copies
the engine consumes, the I2-prescaled inverse tables, and the bit-reversal permutation).
Root tables are ported verbatim from s2morrow (MIT) and independently re-verified by
`scripts/verify_ntt_constants.py`.

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| forward 512-point transform | 8,895,740 | 81,826 |
| forward 512-point transform, unreduced output (`ntt_lazy`) | 7,832,270 | 73,587 |
| forward + inverse roundtrip | 22,725,980 | 211,044 |
