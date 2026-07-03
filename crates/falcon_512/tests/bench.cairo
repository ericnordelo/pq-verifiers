//! Benchmark scenarios for the Falcon-512 (BLAKE2s hash-to-point, hint-based) verifier.
//!
//! Measurement method (paired-test subtraction): the harness runs `bench_verify_*` and
//! `bench_baseline_*`, which build IDENTICAL inputs; only the former calls `verify`. The
//! per-scheme verification cost is `verify_total - baseline_total` for each metric.
//!
//! Each hash-to-point construction (BLAKE2s and Poseidon) has its own genuine fixture
//! (reference falcon.py sampler; regenerate with `scripts/gen_falcon_fixture.py
//! [--hash poseidon]`), and both verify variants share it (the direct signature is the
//! 31-felt prefix of the hint one). The non-bench tests below are the correctness gate:
//! the fixtures verify, and any tampering — signature, hint, salt, message, or public
//! key — is rejected.

use pqbench_falcon_512::bench_fixture::{msg, public_key, signature};
use pqbench_falcon_512::bench_fixture_poseidon::{
    msg as msg_p, public_key as public_key_p, signature as signature_p,
};
use pqbench_falcon_512::{
    Falcon512DirectVerifier, Falcon512PoseidonDirectVerifier, Falcon512PoseidonVerifier,
    Falcon512Verifier,
};
use pqbench_interface::PqSignatureVerifier;

/// Direct-variant signature: the s1 || salt prefix of a hint-layout signature.
fn sig_prefix_31(sig: Span<felt252>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut prefix = sig.slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
}

fn signature_direct() -> Array<felt252> {
    sig_prefix_31(signature().span())
}

/// Builds the inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512() {
    let pk = public_key();
    let sig = signature();
    assert!(pk.len() == 29 && sig.len() == 60);
}

/// Builds the inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512() {
    let pk = public_key();
    let sig = signature();
    let valid = Falcon512Verifier::verify(msg(), pk.span(), sig.span());
    assert!(valid);
}

/// Builds the direct-variant inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512_direct() {
    let pk = public_key();
    let sig = signature_direct();
    assert!(pk.len() == 29 && sig.len() == 31);
}

/// Builds the direct-variant inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512_direct() {
    let pk = public_key();
    let sig = signature_direct();
    let valid = Falcon512DirectVerifier::verify(msg(), pk.span(), sig.span());
    assert!(valid);
}

#[test]
fn test_falcon_512_direct_rejects_tampering() {
    let pk = public_key();
    let sig = signature_direct();
    assert!(!Falcon512DirectVerifier::verify('OTHER_MSG', pk.span(), sig.span()));
    // Tampered salt changes the msg_point: norm check fails.
    let bad_salt = with_felt_replaced(sig.span(), 29, *sig.span().at(29) + 1);
    assert!(!Falcon512DirectVerifier::verify(msg(), pk.span(), bad_salt.span()));
    // Swapped (still canonical) s1 felts no longer solve the equation.
    let a = *sig.span().at(0);
    let b = *sig.span().at(1);
    let bad_s1 = with_felt_replaced(with_felt_replaced(sig.span(), 0, b).span(), 1, a);
    assert!(!Falcon512DirectVerifier::verify(msg(), pk.span(), bad_s1.span()));
    // The 60-felt hint layout is not valid for the direct scheme.
    assert!(!Falcon512DirectVerifier::verify(msg(), pk.span(), signature().span()));
}

/// Builds the Poseidon hint-variant inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512_poseidon() {
    let pk = public_key_p();
    let sig = signature_p();
    assert!(pk.len() == 29 && sig.len() == 60);
}

/// Builds the Poseidon hint-variant inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512_poseidon() {
    let pk = public_key_p();
    let sig = signature_p();
    let valid = Falcon512PoseidonVerifier::verify(msg_p(), pk.span(), sig.span());
    assert!(valid);
}

/// Builds the Poseidon direct-variant inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_falcon_512_poseidon_direct() {
    let pk = public_key_p();
    let sig = sig_prefix_31(signature_p().span());
    assert!(pk.len() == 29 && sig.len() == 31);
}

/// Builds the Poseidon direct-variant inputs and verifies — the measured scenario.
#[test]
fn bench_verify_falcon_512_poseidon_direct() {
    let pk = public_key_p();
    let sig = sig_prefix_31(signature_p().span());
    let valid = Falcon512PoseidonDirectVerifier::verify(msg_p(), pk.span(), sig.span());
    assert!(valid);
}

#[test]
fn test_falcon_512_poseidon_rejects_tampering() {
    let pk = public_key_p();
    let sig = signature_p();
    assert!(!Falcon512PoseidonVerifier::verify('OTHER_MSG', pk.span(), sig.span()));
    // Tampered salt changes the msg_point: norm check fails.
    let bad_salt = with_felt_replaced(sig.span(), 29, *sig.span().at(29) + 1);
    assert!(!Falcon512PoseidonVerifier::verify(msg_p(), pk.span(), bad_salt.span()));
    // Swapped (still canonical) s1 felts no longer match the hint / equation.
    let a = *sig.span().at(0);
    let b = *sig.span().at(1);
    let bad_s1 = with_felt_replaced(with_felt_replaced(sig.span(), 0, b).span(), 1, a);
    assert!(!Falcon512PoseidonVerifier::verify(msg_p(), pk.span(), bad_s1.span()));
    // Swapped hint felts fail the pointwise product check.
    let h1 = *sig.span().at(31);
    let h2 = *sig.span().at(32);
    let bad_hint = with_felt_replaced(with_felt_replaced(sig.span(), 31, h2).span(), 32, h1);
    assert!(!Falcon512PoseidonVerifier::verify(msg_p(), pk.span(), bad_hint.span()));
    // Wrong lengths are rejected.
    assert!(!Falcon512PoseidonVerifier::verify(msg_p(), pk.span(), sig.span().slice(0, 59)));
}

#[test]
fn test_falcon_512_poseidon_direct_rejects_tampering() {
    let pk = public_key_p();
    let sig = sig_prefix_31(signature_p().span());
    assert!(!Falcon512PoseidonDirectVerifier::verify('OTHER_MSG', pk.span(), sig.span()));
    let bad_salt = with_felt_replaced(sig.span(), 29, *sig.span().at(29) + 1);
    assert!(!Falcon512PoseidonDirectVerifier::verify(msg_p(), pk.span(), bad_salt.span()));
    let a = *sig.span().at(0);
    let b = *sig.span().at(1);
    let bad_s1 = with_felt_replaced(with_felt_replaced(sig.span(), 0, b).span(), 1, a);
    assert!(!Falcon512PoseidonDirectVerifier::verify(msg_p(), pk.span(), bad_s1.span()));
    // The 60-felt hint layout is not valid for the direct scheme.
    assert!(!Falcon512PoseidonDirectVerifier::verify(msg_p(), pk.span(), signature_p().span()));
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
fn test_falcon_512_rejects_wrong_message() {
    assert!(!Falcon512Verifier::verify('OTHER_MSG', public_key().span(), signature().span()));
}

#[test]
fn test_falcon_512_rejects_tampered_s1() {
    let sig = signature();
    // Swap two canonical s1 felts: still unpacks, but the signature no longer matches.
    let a = *sig.span().at(0);
    let b = *sig.span().at(1);
    let tampered = with_felt_replaced(
        with_felt_replaced(sig.span(), 0, b).span(), 1, a,
    );
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), tampered.span()));
    // Non-canonical s1 encoding (packed half overflows Q^9).
    let noncanonical = with_felt_replaced(
        signature().span(), 0, 6392178558614694273495691177456939009,
    );
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), noncanonical.span()));
}

#[test]
fn test_falcon_512_rejects_tampered_hint() {
    let sig = signature();
    let a = *sig.span().at(31);
    let b = *sig.span().at(32);
    let tampered = with_felt_replaced(
        with_felt_replaced(sig.span(), 31, b).span(), 32, a,
    );
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_rejects_tampered_salt() {
    let sig = signature();
    let flipped = *sig.span().at(29) + 1;
    let tampered = with_felt_replaced(sig.span(), 29, flipped);
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_rejects_tampered_public_key() {
    let pk = public_key();
    let a = *pk.span().at(0);
    let b = *pk.span().at(1);
    let tampered = with_felt_replaced(with_felt_replaced(pk.span(), 0, b).span(), 1, a);
    assert!(!Falcon512Verifier::verify(msg(), tampered.span(), signature().span()));
}

#[test]
fn test_falcon_512_rejects_bad_lengths() {
    let pk = public_key();
    let sig = signature();
    assert!(!Falcon512Verifier::verify(msg(), pk.span().slice(0, 28), sig.span()));
    assert!(!Falcon512Verifier::verify(msg(), pk.span(), sig.span().slice(0, 59)));
    assert!(!Falcon512Verifier::verify(msg(), array![].span(), array![].span()));
}
