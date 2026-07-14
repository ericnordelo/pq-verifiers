//! Benchmark scenarios for the Falcon-512 verifier with the STANDARD SHAKE-256
//! hash-to-point (hint and direct).
//!
//! Measurement method (paired-test subtraction): the harness runs `bench_verify_*` and
//! `bench_baseline_*`, which build IDENTICAL inputs; only the former calls `verify`. The
//! per-scheme verification cost is `verify_total - baseline_total` for each metric.
//!
//! The fixture is a genuine standards-compliant signature (reference falcon.py sampler +
//! falcon.py's own SHAKE-256 hash-to-point; regenerate with
//! `scripts/gen_falcon_fixture.py --variant shake`). The non-bench tests are the
//! correctness gate: the fixture verifies, and tampering with the message, salt, s1, or
//! length is rejected — with the message/salt cases specifically exercising the
//! SHAKE-256 hash-to-point path.

use pqbench_falcon_512::fixtures::shake::{msg, public_key, signature};
use pqbench_falcon_512::{Falcon512ShakeDirectVerifier, Falcon512ShakeVerifier};
use pqbench_interface::PqSignatureVerifier;

/// Builds the inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512_shake() {
    let pk = public_key();
    let sig = signature();
    assert!(pk.len() == 29 && sig.len() == 60);
}

/// Builds the inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512_shake() {
    let pk = public_key();
    let sig = signature();
    let valid = Falcon512ShakeVerifier::verify(msg(), pk.span(), sig.span());
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
fn test_falcon_512_shake_rejects_wrong_message() {
    // Exercises the SHAKE-256 hash-to-point: a different message yields a different point.
    assert!(!Falcon512ShakeVerifier::verify('OTHER_MSG', public_key().span(), signature().span()));
}

#[test]
fn test_falcon_512_shake_rejects_tampered_salt() {
    // Exercises the SHAKE-256 hash-to-point: a different salt yields a different point.
    let sig = signature();
    let tampered = with_felt_replaced(sig.span(), 29, *sig.span().at(29) + 1);
    assert!(!Falcon512ShakeVerifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_shake_rejects_oversized_salt() {
    let sig = signature();
    let too_big: felt252 = 0x10000000000000000000000000000000000000000;
    let oversized_a = with_felt_replaced(sig.span(), 29, too_big);
    let oversized_b = with_felt_replaced(sig.span(), 30, too_big);
    assert!(!Falcon512ShakeVerifier::verify(msg(), public_key().span(), oversized_a.span()));
    assert!(!Falcon512ShakeVerifier::verify(msg(), public_key().span(), oversized_b.span()));
}

#[test]
fn test_falcon_512_shake_rejects_tampered_s1() {
    let sig = signature();
    // Swap two canonical s1 felts: still unpacks, but the signature no longer matches.
    let a = *sig.span().at(0);
    let b = *sig.span().at(1);
    let tampered = with_felt_replaced(with_felt_replaced(sig.span(), 0, b).span(), 1, a);
    assert!(!Falcon512ShakeVerifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_shake_rejects_bad_lengths() {
    let pk = public_key();
    let sig = signature();
    assert!(!Falcon512ShakeVerifier::verify(msg(), pk.span().slice(0, 28), sig.span()));
    assert!(!Falcon512ShakeVerifier::verify(msg(), pk.span(), sig.span().slice(0, 59)));
}

/// The direct-variant signature: the 31-felt `s1 || salt` prefix of the hint fixture.
fn signature_direct() -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut prefix = signature().span().slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
}

/// Builds the direct-variant inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512_shake_direct() {
    let pk = public_key();
    let sig = signature_direct();
    assert!(pk.len() == 29 && sig.len() == 31);
}

/// Builds the direct-variant inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512_shake_direct() {
    let pk = public_key();
    let sig = signature_direct();
    let valid = Falcon512ShakeDirectVerifier::verify(msg(), pk.span(), sig.span());
    assert!(valid);
}

#[test]
fn test_falcon_512_shake_direct_rejects_wrong_message() {
    // Exercises the SHAKE-256 hash-to-point over the direct core.
    let bad = Falcon512ShakeDirectVerifier::verify(
        'OTHER_MSG', public_key().span(), signature_direct().span(),
    );
    assert!(!bad);
}


#[test]
fn test_falcon_512_shake_direct_rejects_oversized_salt() {
    let sig = signature_direct();
    let too_big: felt252 = 0x10000000000000000000000000000000000000000;
    let oversized_a = with_felt_replaced(sig.span(), 29, too_big);
    let oversized_b = with_felt_replaced(sig.span(), 30, too_big);
    assert!(!Falcon512ShakeDirectVerifier::verify(msg(), public_key().span(), oversized_a.span()));
    assert!(!Falcon512ShakeDirectVerifier::verify(msg(), public_key().span(), oversized_b.span()));
}
