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

The crate also exposes generated fixed-parameter forward paths for n = 512 and q = 12289:
`ntt_falcon512_fast_unchecked` for felt coefficients and
`ntt_falcon512_fast_u16_unchecked` for the verifier's canonical internal representation.
Their names make the unchecked `[0, q)` coefficient precondition explicit; callers handling
untrusted inputs must validate them first. The verifier does so during canonical base-Q
unpacking. Their shared butterfly graph is straight-line Cairo, with no runtime level/block
loops or root-table traversal; each output is reduced once after the graph. The generic
engine remains the parameterized implementation and correctness oracle.
`scripts/gen_ntt_tables.py --emit` derives the fast path from the same verified root tables,
proves its unreduced integer graph equivalent to the recursive reference, and proves every
shifted output fits in u128 for canonical inputs before emitting the source.

The safety argument for the delayed reduction (bound tracking, offsets, the 2^126
threshold) is documented in `src/engine.cairo` and kept executable by
`scripts/gen_ntt_tables.py`, which proves the engine equal to the recursive reference
on random and adversarial inputs and generates the derived tables (the felt252 copies
the engine consumes, the I2-prescaled inverse tables, the bit-reversal permutation, and
the generated Falcon-512 fast path).
Root tables are ported verbatim from s2morrow (MIT) and independently re-verified by
`scripts/verify_ntt_constants.py`.

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| forward 512-point transform | 8,895,740 | 81,826 |
| forward 512-point transform, unreduced output (`ntt_lazy`) | 7,832,270 | 73,587 |
| generated Falcon-512 transform (felt input) | 2,137,010 | 15,635 |
| generated Falcon-512 transform (`u16` input) | 2,137,010 | 15,635 |
| forward + inverse roundtrip | 22,725,980 | 211,044 |
