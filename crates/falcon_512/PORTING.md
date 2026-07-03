# Falcon-512 verifier — port plan

Status: **implemented** (direct-NTT variant). Kept as the record of the port.
with a real Falcon-512 verifier, derived from reading the reference implementation.

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
