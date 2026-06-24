# AGENTS.md — conventions for this repository

Guidance for any agent or contributor editing this repo. Follow it so the project stays
consistent and publish-ready. (Applies to the whole repository; nested files, if any,
override for their subtree.)

## What this repo is

A **public, self-contained** benchmark comparing post-quantum signature verifiers for a
Starknet account, by on-chain verification cost. The audience is the Starknet/StarkWare
ecosystem and OpenZeppelin. It will later inform a production account component, but it is
**not** part of any library here and must read as a standalone project.

## Golden rules

1. **Self-contained.** Dependencies come from the Scarb registry only. Never introduce
   `path = "../.."` dependencies on a parent repository, or any `../../` references in docs
   or links. The internal `pqbench_*` crates may path-depend on each other.
2. **Write for an external reader.** No framing as internal library/developer documentation:
   do not mention "the main library", monorepo location, internal release processes, or
   contributor-only tooling. Explain things for someone seeing the repo cold on GitHub.
3. **Never commit unverified cryptography.** A real verifier must be validated by a fixture
   it accepts (a genuine signature) *and* rejects when tampered, before `"implemented": true`.
   Stubs are allowed but must be labelled as such and excluded from headline numbers.
4. **Results are generated, not hand-edited.** Regenerate `results/` with `make all`.
5. **Keep the toolchain pinned** in `.tool-versions`. If you change it, say why in the README.
6. **Date the README** (`Last updated:`) whenever you change what it describes.

## The measurement contract (do not break)

- Every verifier implements `PqSignatureVerifier` from `crates/bench_interface`:
  `fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool`.
- Costs are isolated by **paired-test subtraction**. Test names are a fixed convention the
  scripts rely on:
  - bare verify: `bench_verify_<key>` and `bench_baseline_<key>`
  - in-`__validate__`: `bench_validate_<key>` and `bench_validate_base_<key>`
  The baseline must build identical inputs and differ only by omitting the measured call.
- `schemes.json` is the single registry. Each entry's `verify_test` / `baseline_test` /
  `validate_test` / `validate_baseline_test` / `contract` must match real test and contract
  names. Sizes (`sig_felts`, `pubkey_felts`) must reflect the real encoding once implemented.

## Adding a scheme (the only supported flow)

1. Create `crates/<key>/` with `Scarb.toml`, `src/lib.cairo` (the `PqSignatureVerifier` impl),
   and a short `README.md` (format below).
2. Add `crates/<key>/tests/bench.cairo` with the paired `bench_verify_*` / `bench_baseline_*`.
3. (For the realistic scenario) add an account mock in `crates/bench_targets` and paired
   `bench_validate_*` / `bench_validate_base_*`.
4. Add `crates/<key>` to `members` in `Scarb.toml`.
5. Add the `schemes.json` entry (`"implemented": true` only once validated by a real fixture).
6. `make all`, then commit the regenerated `results/`.

## Per-crate README format (verifier crates)

Keep it to a few lines. Required shape:

```
# <Scheme name> verifier

**Scheme:** <name> — <family>, <standardization status>.
**Status:** <measured | stub (pending implementation)>.

<One or two sentences: what it is and why it is a candidate (or, for the baseline, why it is
only a control).>

Implements `PqSignatureVerifier`. <Link(s) to deeper detail: spec / NIST FIPS / reference impl.>
```

## Verify before you finish

`make test` must show all tests passing, and `make all` must regenerate `results/report.html`
without errors.
