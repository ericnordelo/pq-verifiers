# Falcon-512 verifier — port plan

Status: **implemented and measured** (all six steps done). Decisions taken, where they
deviate from or refine the plan below:

- **NTT**: delegated to the shared engine crate (`crates/ntt`): the split/merge transform
  reformulated iteratively with felt252 lazy reduction (~8.9M l2_gas per forward 512-point
  transform, ~13.8M per inverse — down from ~33M for the eager looped port this crate
  originally embedded). Root tables (moved verbatim to `crates/ntt/src/roots.cairo`) are
  independently verified by `scripts/verify_ntt_constants.py`, including a cross-check
  against tprest/falcon.py that pins the interop convention; the engine itself is proven
  against the recursive reference by `scripts/gen_ntt_tables.py` and the in-crate oracle
  tests.
- **Variants**: both are registered in `schemes.json` and measured.
  - *Hint-based* (`falcon_512`): 2 forward NTTs; signature carries `mul_hint = s1*h`
    (+29 felts).
  - *Direct* (`falcon_512_direct`): no hint; `s1*h = INTT(NTT(s1) ∘ h_ntt)` — also only
    2 transforms **because the public key is stored NTT-domain**. With a
    coefficient-domain pk the direct method needs a third transform (`NTT(h)`) and busts
    the validation budget: ~125.8M gas / 1.09M steps measured in
    [ericnordelo/pq-verifiers#1](https://github.com/ericnordelo/pq-verifiers/pull/1)
    (which also reports the unrolled NTT tripping the Sierra compiler under snforge, and
    keeps hash-to-point off-chain by carrying `msg_point` in the signature — rejected here
    because an on-chain verifier that never derives `msg_point` from `message_hash` is not
    message-binding: any `(s1, msg_point = s1*h + small)` pair would pass for any message).
- **hash_to_point**: computed **on-chain** (message-binding), with the spec's rejection
  sampling but the XOF instantiated as BLAKE2s in counter mode (`core::blake` builtin)
  instead of SHAKE-256 — NON-standard, chosen for Cairo cost; construction documented in
  `src/hash_to_point.cairo` and mirrored by `scripts/gen_falcon_fixture.py`.
- **Canonical-range validation**: unpacking rejects non-canonical base-Q encodings
  (the "PK coefficients < Q on read" gap flagged below), and oversized salts.
- **Encoding**: pk = 29 felts (packed NTT-domain h); signature = 60 felts
  (packed s1 ‖ 40-byte salt as 2 felts ‖ packed mul_hint).
- **Fixture**: genuine falcon.py keypair + ffSampling signature over the bench message
  (`scripts/gen_falcon_fixture.py`), accepted by the verifier; tampered s1/hint/salt/pk/
  message all rejected (`tests/bench.cairo`). Measured bare verify: ~76M l2_gas.

## Reference

- `feltroidprime/s2morrow` and `starkware-bitcoin/s2morrow`, **MIT licensed** (port with a
  `SPDX-FileCopyrightText` attribution header, as their files carry).
- Modules to port from `packages/falcon/src/`: `zq.cairo`, `ntt.cairo`, `ntt_constants.cairo`,
  `packing.cairo`, `types.cairo`, `hash_to_point.cairo`, `falcon.cairo`, plus the
  `corelib_imports` bounded-int shim (or use `core::internal::bounded_int` directly).

## Algorithm (hint-based verify, as in s2morrow `falcon::verify_with_msg_point`)

Inputs: packed public key `h_ntt` (NTT domain), signature `s1`, verification `mul_hint`,
and `msg_point = SHAKE-256 hash_to_point(message, salt)`.

1. Unpack the 29-felt packed polynomials to 512 `Zq` coefficients each (`packing.cairo`).
2. Two forward NTTs: `ntt_fast(s1)`, `ntt_fast(mul_hint)`.
3. Per coefficient i (fused loop, 8-way unrolled):
   - hint check: `mul_mod(NTT(s1)[i], h_ntt[i]) == NTT(mul_hint)[i]`;
   - accumulate `acc += center_and_square(sub_mod(msg_point[i], mul_hint[i])) + center_and_square(s1[i])`.
4. Accept iff `acc <= SIG_BOUND_512` (= 34_034_726).

Key constants: `Q = 12289`, `Zq = BoundedInt<0, 12288>`, centered norm uses `[0, 6144]` low half.

## Mapping onto the harness `PqSignatureVerifier`

```
verify(message_hash, public_key, signature) -> bool
```

- `public_key`: 29 felts (packed `h_ntt`).
- `signature`: packed `s1` (29 felts) + `salt` + (hint variant) packed `mul_hint` (29 felts).
  Note: the hint variant roughly DOUBLES signature calldata; measure both this and the
  direct-NTT (no hint) variant — the harness supports adding both as separate schemes.
- `message_hash`: our interface passes a single felt; Falcon needs the full message + salt
  for `hash_to_point`. Options: (a) compute `hash_to_point` off-chain and pass `msg_point`
  packed in the signature (s2morrow's interop path), or (b) widen the harness fixture to
  carry `(message, salt)`. Decide when implementing; (a) matches the deployed s2morrow wallet.

## Prerequisites / caveats (from the research brief)

- Experimental `bounded_int` libfuncs — already enabled (`allowed-libfuncs-list = experimental`).
- **Unrolled NTT is a large, hard-to-audit TCB** — prefer a looped+proven NTT or the
  direct-NTT variant; do not ship the unrolled verifier wholesale.
- **Hint soundness is audit-critical** — the reference is missing a "PK coefficients < Q on
  read" check; add canonical-range validation on unpack. Consider the direct-NTT variant
  (`mul_zq`, 2 NTT + 1 INTT, no signer-supplied hint) for a smaller trust surface.

## Fixtures (to validate correctness)

Generate a valid `(h_ntt, message, salt, s1, mul_hint)` off-chain with the Falcon signer
(`falcon.py` / `falcon-rs`), as in s2morrow `tests/test_cross_language.cairo`. Commit it as
the bench fixture so `bench_verify_falcon_512` exercises a real signature (and a negative
test rejects a tampered one). This is the gate that proves the port is correct.

## Steps

1. Port `zq` + a unit test (mod-12289 add/sub/mul round-trips).
2. Port `ntt` + `ntt_constants`; test `INTT(NTT(x)) == x` and a known-answer vector.
3. Port `packing` (+ canonical-range validation) and `types`.
4. Port `hash_to_point` (SHAKE-256) or wire the off-chain msg_point path.
5. Port `falcon::verify`; wire it into `Falcon512Verifier::verify`.
6. Add the real fixture; flip `"implemented": true` in `schemes.json`; re-run the harness.
