# PQ verifiers for Starknet accounts

[![CI](https://img.shields.io/github/actions/workflow/status/ericnordelo/pq-verifiers/efficiency.yml?branch=main&label=CI)](https://github.com/ericnordelo/pq-verifiers/actions/workflows/efficiency.yml)

_Comparing candidate post-quantum signature verifiers for a Starknet account by their
verification cost._

_Last updated: 2026-07-07._

## Why

Starknet's STARK proofs are post-quantum. The ECDSA signatures that authorize account
transactions are not, and Shor's algorithm could forge them. Because Starknet accounts are
smart contracts (account abstraction), a post-quantum account can ship today by swapping the
check inside `__validate__`, provided that verification fits Starknet's validation limits.
This repo measures which schemes fit, and which is cheapest.

## What we measure

For each scheme, the cost of verifying one signature, both alone and inside a real
`__validate__`: L2 gas, Cairo steps, signature and key size, contract class size, and where
the steps go.

Validation is capped at 1,000,000 steps and 100,000,000 L2 gas (blockifier v0.13.4;
both unchanged as of Starknet 0.14.3), so a verifier has to fit under both.

These are resource measurements — steps and builtins priced with the protocol gas table.
Transaction **fees** meter L2 gas differently for Sierra ≥ 1.7 classes and run roughly
twice these values on this workload; receipt-measured costs per deployed account are in
[`pq-accounts/USAGE.md`](pq-accounts/USAGE.md#what-transactions-cost).

## Snapshot

Current efficiency of every measured entry, per crate (the values pinned in
[`efficiency_baseline.json`](efficiency_baseline.json); caps are 100,000,000 L2 gas and
1,000,000 steps):

| Crate | Measurement | L2 gas | Steps | % of gas cap |
|---|---|--:|--:|--:|
| [`ecdsa_stark`](crates/ecdsa_stark) | verify (classical control) | 30,855 | 152 | 0.03% |
| [`falcon_512`](crates/falcon_512) | verify, hint variant (BLAKE2s) | 26,611,400 | 239,795 | 26.6% |
| [`falcon_512`](crates/falcon_512) | verify, direct variant (BLAKE2s) | 31,118,060 | 284,834 | 31.1% |
| [`falcon_512`](crates/falcon_512) | verify, Poseidon variant (native) | 26,488,669 | 237,462 | 26.5% |
| [`falcon_512`](crates/falcon_512) | verify, SHAKE-256 variant (standard) | 63,965,138 | 447,823 | 64.0% |
| [`bench_targets`](crates/bench_targets) | ECDSA-STARK account, inside `__validate__` | 160,795 | 1,437 | 0.16% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 hint account, inside `__validate__` | 28,181,860 | 254,065 | 28.2% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 direct account, inside `__validate__` | 32,637,610 | 298,618 | 32.6% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 Poseidon account, inside `__validate__` | 28,059,129 | 251,731 | 28.1% |
| [`bench_targets`](crates/bench_targets) | Falcon-512 SHAKE-256 account, inside `__validate__` | 65,535,198 | 462,088 | 65.5% |
| [`ntt`](crates/ntt) | forward 512-point transform | 8,895,740 | 81,826 | 8.9% |
| [`ntt`](crates/ntt) | forward transform, unreduced output | 7,832,270 | 73,587 | 7.8% |
| [`ntt`](crates/ntt) | forward + inverse roundtrip | 22,725,980 | 211,044 | 22.7% |
| [`ml_dsa_44`](crates/ml_dsa_44) | verify | stub (not yet measured) | — | — |
| [`poseidon_wots`](crates/poseidon_wots) | verify | stub (not yet measured) | — | — |

ECDSA-STARK is the classical scheme in use today, a cost reference rather than a PQ
candidate. Falcon-512 is the first PQ verifier measured, in four variants that share one
NTT-domain public key and hint-based core: two forward NTTs on the shared lazy-reduction NTT
engine [`crates/ntt`](crates/ntt) (felt252 butterflies), taken unreduced — the verifier folds
the final reduction into its pointwise divisibility check instead of paying reduction passes.
The `direct` variant instead computes `INTT(NTT(s1) ∘ h_ntt)`, trading its inverse transform
for half the signature calldata (31 vs 60 felts) and no signer-supplied hint, at a ~17% cost
premium. The variants otherwise differ only in the on-chain hash-to-point that binds the
message:

- **BLAKE2s** (hint and direct): a non-standard XOF swap via the `core::blake` builtin.
  Nearly the cheapest, but needs a matching signer.
- **Poseidon**: a native `hades_permutation` squeeze. Message-binding, the cheapest variant
  (marginally below BLAKE2s), and the most STARK-proving-friendly since it uses native field
  arithmetic. Also non-standard.
- **SHAKE-256**: the standard Falcon hash-to-point, interoperable with any compliant signer
  (e.g. falcon.py). The pure-Cairo Keccak-f[1600] (flat unrolled rounds, u128 lanes, lazy
  block squeezing) keeps hash-to-point around 0.2M steps, so even the standards-compliant
  variant fits both validation caps — at ~2.4× the cost of the non-standard ones. A native
  `keccak_f1600` syscall ([SNIP-32](https://github.com/starknet-io/SNIPs)) would close the
  remaining gap.

All four use genuine falcon.py-signed fixtures and fit the validation caps — the non-standard
variants with wide margin, SHAKE-256 at about two-thirds of the gas cap and under half the
step cap.

All four derive the message point on-chain from `message_hash`, which binds the signature to
the message. The reference Starknet Falcon verifier
[s2morrow](https://github.com/feltroidprime/s2morrow) instead takes the point as precomputed
calldata and multiplies in the coefficient domain (three transforms); these verifiers derive
the point on-chain and store the public key in the NTT domain (two transforms), so they do
strictly more security-relevant work while keeping the polynomial arithmetic cheaper. Each
variant also has an account contract measured inside `__validate__`, where the realistic cost
sits just above bare verify (the verifier dominates; dispatch, the 29-slot key read, and
deserialization are small). The remaining PQ verifiers are stubs behind the same interface.

## Report

`make report` regenerates these from the latest run:

```
results/report.html      # standalone HTML: sortable table, charts, profiler attribution
results/summary.md       # text summary
results/results.json     # raw data plus metadata
```

## Run

The toolchain is pinned in `.tool-versions` (Scarb 2.18.0, Starknet Foundry 0.59.0,
cairo-profiler 0.16.0, plus starknet-devnet 0.9.0 for the
[`pq-accounts`](pq-accounts/USAGE.md) walkthrough). Install it with
[asdf](https://asdf-vm.com) or [starkup](https://github.com/software-mansion/starkup).

```bash
make all        # measure, profile, then render the report
make test       # run the test suite
make check-eff  # efficiency ratchet: fail if any tracked cost regressed
make ratchet    # lock measured improvements into efficiency_baseline.json
```

Efficiency is a one-way ratchet: `efficiency_baseline.json` pins the cost of every
tracked benchmark pair (L2 gas and steps), CI fails any change that raises a number,
and improvements are committed via `make ratchet`.

## Schemes

| Crate | Scheme | Family | Standardization |
|---|---|---|---|
| [`ecdsa_stark`](crates/ecdsa_stark) | ECDSA-STARK | classical EC (control) | none |
| [`falcon_512`](crates/falcon_512) | Falcon-512 (FN-DSA); BLAKE2s hint+direct, SHAKE-256, Poseidon variants | lattice (NTRU) | draft, FIPS 206 (standard SHAKE-256; non-standard BLAKE2s / Poseidon) |
| [`ml_dsa_44`](crates/ml_dsa_44) | ML-DSA-44 (Dilithium) | lattice (module) | final, FIPS 204 |
| [`poseidon_wots`](crates/poseidon_wots) | Poseidon-WOTS+ | hashing | not standardized |

## Method

Every scheme implements the one interface in
[`crates/bench_interface`](crates/bench_interface); each cost is the measured test minus a
baseline test that builds the same inputs but omits the verify call. Bare verify covers the
function alone. The validate scenario deploys an account mock from
[`crates/bench_targets`](crates/bench_targets) and calls it, which adds dispatch,
signature deserialization, and a storage read. Numbers come from Starknet Foundry (gas,
steps, builtins), a release build (class size), and cairo-profiler (attribution by
function).

## Layout

```
crates/
  bench_interface/   # the common PqSignatureVerifier interface plus cap constants
  ecdsa_stark/       # one crate per scheme (see each crate's README)
  falcon_512/
  ml_dsa_44/
  poseidon_wots/
  ntt/               # shared lazy-reduction NTT engine (used by the lattice schemes)
  bench_targets/     # one account contract per verifier, for the validate scenario
scripts/             # run_bench.py, profile.py, gen_report.py, check_efficiency.py
schemes.json         # the scheme registry
efficiency_baseline.json  # the efficiency ratchet (CI-enforced)
results/             # generated report plus committed snapshot
```

Adding a scheme is documented in [`AGENTS.md`](AGENTS.md).

## References

- Falcon / FN-DSA: [spec](https://falcon-sign.info/falcon.pdf) ·
  [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-DSA / FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) ·
  [SLH-DSA / FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf)
- Reference Falcon wallet on Starknet: [s2morrow](https://github.com/feltroidprime/s2morrow)
- Starknet [fees](https://docs.starknet.io/learn/protocol/fees) ·
  [accounts](https://docs.starknet.io/learn/protocol/accounts)

## License

MIT. See [LICENSE](LICENSE).
