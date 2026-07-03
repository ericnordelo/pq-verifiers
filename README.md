# PQ verifiers for Starknet accounts

_Comparing candidate post quantum signature verifiers for a Starknet account by their
verification cost. Maintained by OpenZeppelin. Last updated: July 3, 2026._

## Why

Starknet's STARK proofs are post quantum. The ECDSA signatures that authorize account
transactions are not, and Shor's algorithm could forge them. Because Starknet accounts are
smart contracts (account abstraction), a post quantum account can ship today by swapping the
check inside `__validate__`, provided that verification fits Starknet's validation limits.
This repo measures which scheme fits, and which does it most efficiently.

## What we measure

For each scheme, the cost of verifying one signature, both alone and inside a real
`__validate__`: L2 gas, Cairo steps, signature and key size, contract class size, and where
the steps go.

Validation is capped at 1,000,000 steps and 100,000,000 L2 gas (blockifier v0.13.4), so a
verifier has to fit under both.

## Snapshot

![Benchmark summary](results/report.svg)

| Scheme | Status | Verify (L2 gas) | Inside `__validate__` (L2 gas) | % of gas cap |
|---|---|--:|--:|--:|
| ECDSA-STARK | baseline (classical control) | 30,855 | 160,795 | 0.16% |
| Falcon-512 (hint, BLAKE2s) | measured (bare verify) | 76,251,800 | — | 76.3% |
| Falcon-512 direct (BLAKE2s) | measured (bare verify) | 76,153,920 | — | 76.2% |
| Falcon-512 Poseidon (hint) | measured (bare verify) | 75,810,314 | — | 75.8% |
| Falcon-512 Poseidon direct | measured (bare verify) | 75,712,434 | — | 75.7% |
| ML-DSA-44 | pending | — | — | — |
| Poseidon-WOTS+ | pending | — | — | — |

ECDSA-STARK is the classical scheme in use today, a cost reference rather than a PQ
candidate. Falcon-512 is the first PQ verifier measured, in four schemes sharing one
NTT-domain public key: two verify variants (hint vs direct) crossed with two on-chain
hash-to-point constructions (BLAKE2s counter-mode XOF vs s2morrow's deployed Poseidon
sponge — both non-standard swaps of the spec's SHAKE-256). Each construction is validated
by its own genuine falcon.py-signed fixture, and all four fit the validation caps at
~76% of L2 gas / ~66% of steps. The two 512-point NTT transforms dominate; the hash choice
moves the bill by only ~0.4M gas (Poseidon cheaper), and the direct variant carries half
the signature calldata (31 vs 60 felts) with no signer-supplied hint — making
**Falcon-512 Poseidon direct** the cheapest configuration. (With a coefficient-domain key
the direct method needs a third transform and busts the budget — measured in
[ericnordelo/pq-verifiers#1](https://github.com/ericnordelo/pq-verifiers/pull/1).)
The remaining PQ verifiers are scaffolded behind the same interface (see `crates/`).

## Report

`make report` regenerates these from the latest run, and the README image updates with it:

```
results/report.html      # rich view: sortable table, charts, profiler attribution
results/report.svg        # the summary image above
results/summary.md        # text summary
results/results.json      # raw data plus metadata
```

## Run

The toolchain is pinned in `.tool-versions` (Scarb 2.18.0, Starknet Foundry 0.59.0,
cairo-profiler 0.16.0). Install it with [asdf](https://asdf-vm.com) or
[starkup](https://github.com/software-mansion/starkup).

```bash
make all        # measure, profile, then render the report
make test       # run the test suite
```

## Schemes

| Crate | Scheme | Family | Standardization |
|---|---|---|---|
| [`ecdsa_stark`](crates/ecdsa_stark) | ECDSA-STARK | classical EC (control) | none |
| [`falcon_512`](crates/falcon_512) | Falcon-512 (FN-DSA), {hint, direct} x {BLAKE2s, Poseidon} | lattice (NTRU) | draft, FIPS 206 (hash-to-point swapped) |
| [`ml_dsa_44`](crates/ml_dsa_44) | ML-DSA-44 (Dilithium) | lattice (module) | final, FIPS 204 |
| [`poseidon_wots`](crates/poseidon_wots) | Poseidon-WOTS+ | hashing | not standardized |

## Method

Each cost is isolated by subtracting a baseline test (same inputs, no verify call) from the
measured one. Bare verify covers the function alone. The validate scenario deploys an account
mock and calls it, which adds dispatch, signature deserialization, and a storage read.
Numbers come from Starknet Foundry (gas, steps, builtins), a release build (class size), and
cairo-profiler (attribution by function).

## Layout

```
crates/
  bench_interface/   # the common PqSignatureVerifier interface plus cap constants
  ecdsa_stark/       # one crate per scheme (see each crate's README)
  falcon_512/
  ml_dsa_44/
  poseidon_wots/
  bench_targets/     # account mock contracts for the validate scenario
scripts/             # run_bench.py, profile.py, gen_report.py
schemes.json         # the scheme registry
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
