//! Benchmark scenarios for the ECDSA-STARK baseline verifier.
//!
//! Measurement method (paired-test subtraction): the harness runs `bench_verify_*` and
//! `bench_baseline_*`, which build IDENTICAL inputs; only the former calls `verify`. The
//! per-scheme verification cost is `verify_total - baseline_total` for each metric (steps,
//! L2 gas), which cancels out test-harness and input-construction overhead.

use openzeppelin_testing::constants::stark::KEY_PAIR;
use openzeppelin_testing::signing::SerializedSigning;
use pqbench_ecdsa_stark::EcdsaStarkVerifier;
use pqbench_interface::PqSignatureVerifier;

const MSG: felt252 = 'BENCH_MSG';

/// Builds the inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let public_key = array![key_pair.public_key];
    assert!(signature.len() == 2);
    assert!(public_key.len() == 1);
}

/// Builds the inputs and verifies — the measured scenario.
#[test]
fn bench_verify_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let public_key = array![key_pair.public_key];
    let valid = EcdsaStarkVerifier::verify(MSG, public_key.span(), signature.span());
    assert!(valid);
}
