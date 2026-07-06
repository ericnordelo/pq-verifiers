//! Benchmark scenario for the Falcon-512 verifier with the native-Poseidon hash-to-point
//! (hint-based).
//!
//! Measurement method (paired-test subtraction): the harness runs `bench_verify_*` and
//! `bench_baseline_*`, which build IDENTICAL inputs; only the former calls `verify`. The
//! per-scheme verification cost is `verify_total - baseline_total` for each metric.
//!
//! The fixture is a genuine signature (reference falcon.py sampler + the Poseidon
//! hash-to-point; regenerate with `scripts/gen_falcon_fixture.py --variant poseidon`). The
//! non-bench tests are the correctness gate: the fixture verifies, and tampering with the
//! message, salt, s1, or length is rejected — with the message/salt cases specifically
//! exercising the Poseidon hash-to-point path.

use pqbench_falcon_512::Falcon512PoseidonVerifier;
use pqbench_falcon_512::fixtures::poseidon::{msg, public_key, signature};
use pqbench_interface::PqSignatureVerifier;

/// Builds the inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512_poseidon() {
    let pk = public_key();
    let sig = signature();
    assert!(pk.len() == 29 && sig.len() == 60);
}

/// Builds the inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512_poseidon() {
    let pk = public_key();
    let sig = signature();
    let valid = Falcon512PoseidonVerifier::verify(msg(), pk.span(), sig.span());
    assert!(valid);
}

/// Copy of `src` with `src[index]` replaced by `value`.
fn with_felt_replaced(mut src: Span<felt252>, index: u32, value: felt252) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut i: u32 = 0;
    while let Some(f) = src.pop_front() {
        if i == index {
            out.append(value);
        } else {
            out.append(*f);
        }
        i += 1;
    }
    out
}

#[test]
fn test_falcon_512_poseidon_rejects_wrong_message() {
    // Exercises the Poseidon hash-to-point: a different message yields a different point.
    assert!(
        !Falcon512PoseidonVerifier::verify('OTHER_MSG', public_key().span(), signature().span()),
    );
}

#[test]
fn test_falcon_512_poseidon_rejects_tampered_salt() {
    // Exercises the Poseidon hash-to-point: a different salt yields a different point.
    let sig = signature();
    let tampered = with_felt_replaced(sig.span(), 29, *sig.span().at(29) + 1);
    assert!(!Falcon512PoseidonVerifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_poseidon_rejects_tampered_s1() {
    let sig = signature();
    // Swap two canonical s1 felts: still unpacks, but the signature no longer matches.
    let a = *sig.span().at(0);
    let b = *sig.span().at(1);
    let tampered = with_felt_replaced(with_felt_replaced(sig.span(), 0, b).span(), 1, a);
    assert!(!Falcon512PoseidonVerifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_poseidon_rejects_bad_lengths() {
    let pk = public_key();
    let sig = signature();
    assert!(!Falcon512PoseidonVerifier::verify(msg(), pk.span().slice(0, 28), sig.span()));
    assert!(!Falcon512PoseidonVerifier::verify(msg(), pk.span(), sig.span().slice(0, 59)));
}
