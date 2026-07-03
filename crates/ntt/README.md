# NTT engine

**Component:** Number-Theoretic Transform (fast negacyclic polynomial multiplication),
shared by the lattice verifiers.
**Status:** measured (see `efficiency_baseline.json`: forward 512 ≈ 8.9M L2 gas,
roundtrip ≈ 22.7M).

A modular, scheme-agnostic NTT optimized for the Cairo cost model: butterfly arithmetic
runs natively in felt252 (one field multiplication and a few additions each, no per
operation reduction), and values are reduced in at most two u128 passes per transform.
Parameter sets plug in through `NttConfig` (modulus, root tables, permutation):
`falcon512` ships the production set (q = 12289, tprest/falcon.py interop order, same
convention as s2morrow); other schemes can add their own without touching the engine.

The safety argument for the delayed reduction (bound tracking, offsets, the 2^126
threshold) is documented in `src/engine.cairo` and kept executable by
`scripts/gen_ntt_tables.py`, which proves the engine equal to the recursive reference
on random and adversarial inputs and generates the derived tables. Root tables are
ported verbatim from s2morrow (MIT) and independently re-verified by
`scripts/verify_ntt_constants.py`.
