//! Benchmark scenarios for the Falcon-512 verifiers with the BLAKE2s hash-to-point (the
//! hint and direct variants).
//!
//! Measurement method (paired-test subtraction): the harness runs `bench_verify_*` and
//! `bench_baseline_*`, which build IDENTICAL inputs; only the former calls `verify`. The
//! per-scheme verification cost is `verify_total - baseline_total` for each metric.
//!
//! The fixture is a genuine signature (reference falcon.py sampler + the BLAKE2s
//! hash-to-point; regenerate with `scripts/gen_falcon_fixture.py`). The non-bench tests
//! below are the correctness gate: the fixture verifies, and any tampering — signature,
//! hint, salt, message, or public key — is rejected.

use pqbench_falcon_512::fixtures::blake::{msg, public_key, signature};
use pqbench_falcon_512::{Falcon512DirectVerifier, Falcon512Verifier};
use pqbench_interface::PqSignatureVerifier;

/// Q^9, the first value outside a canonical full packed half.
const NONCANONICAL_PACKED_HALF: felt252 = 6392178558614694273495691177456939009;
/// 2^160, the first salt-half value that does not fit the 20-byte encoding.
const OVERSIZED_SALT: felt252 = 0x10000000000000000000000000000000000000000;

/// Direct-variant signature: the s1 || salt prefix of the fixture signature.
fn signature_direct() -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut prefix = signature().span().slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
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

#[test]
fn test_falcon_512_direct_rejects_noncanonical_packing() {
    let pk = public_key();
    let sig = signature_direct();
    let noncanonical_pk = with_felt_replaced(pk.span(), 0, NONCANONICAL_PACKED_HALF);
    let noncanonical_s1 = with_felt_replaced(sig.span(), 0, NONCANONICAL_PACKED_HALF);
    assert!(!Falcon512DirectVerifier::verify(msg(), noncanonical_pk.span(), sig.span()));
    assert!(!Falcon512DirectVerifier::verify(msg(), pk.span(), noncanonical_s1.span()));
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
    let tampered = with_felt_replaced(with_felt_replaced(sig.span(), 0, b).span(), 1, a);
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), tampered.span()));
    // Non-canonical s1 encoding (packed half overflows Q^9).
    let noncanonical = with_felt_replaced(signature().span(), 0, NONCANONICAL_PACKED_HALF);
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), noncanonical.span()));
}

#[test]
fn test_falcon_512_rejects_tampered_hint() {
    let sig = signature();
    let a = *sig.span().at(31);
    let b = *sig.span().at(32);
    let tampered = with_felt_replaced(with_felt_replaced(sig.span(), 31, b).span(), 32, a);
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), tampered.span()));
    let noncanonical = with_felt_replaced(sig.span(), 31, NONCANONICAL_PACKED_HALF);
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), noncanonical.span()));
}

#[test]
fn test_falcon_512_rejects_tampered_salt() {
    let sig = signature();
    let flipped = *sig.span().at(29) + 1;
    let tampered = with_felt_replaced(sig.span(), 29, flipped);
    assert!(!Falcon512Verifier::verify(msg(), public_key().span(), tampered.span()));
}

#[test]
fn test_falcon_512_rejects_oversized_salt() {
    let pk = public_key();
    let sig = signature();
    let sig_direct = signature_direct();
    let oversized_hint_a = with_felt_replaced(sig.span(), 29, OVERSIZED_SALT);
    let oversized_hint_b = with_felt_replaced(sig.span(), 30, OVERSIZED_SALT);
    let oversized_direct_a = with_felt_replaced(sig_direct.span(), 29, OVERSIZED_SALT);
    let oversized_direct_b = with_felt_replaced(sig_direct.span(), 30, OVERSIZED_SALT);
    assert!(!Falcon512Verifier::verify(msg(), pk.span(), oversized_hint_a.span()));
    assert!(!Falcon512Verifier::verify(msg(), pk.span(), oversized_hint_b.span()));
    assert!(!Falcon512DirectVerifier::verify(msg(), pk.span(), oversized_direct_a.span()));
    assert!(!Falcon512DirectVerifier::verify(msg(), pk.span(), oversized_direct_b.span()));
}

#[test]
fn test_falcon_512_rejects_tampered_public_key() {
    let pk = public_key();
    let a = *pk.span().at(0);
    let b = *pk.span().at(1);
    let tampered = with_felt_replaced(with_felt_replaced(pk.span(), 0, b).span(), 1, a);
    assert!(!Falcon512Verifier::verify(msg(), tampered.span(), signature().span()));
    let noncanonical = with_felt_replaced(pk.span(), 0, NONCANONICAL_PACKED_HALF);
    assert!(!Falcon512Verifier::verify(msg(), noncanonical.span(), signature().span()));
}

#[test]
fn test_falcon_512_rejects_bad_lengths() {
    let pk = public_key();
    let sig = signature();
    assert!(!Falcon512Verifier::verify(msg(), pk.span().slice(0, 28), sig.span()));
    assert!(!Falcon512Verifier::verify(msg(), pk.span(), sig.span().slice(0, 59)));
    assert!(!Falcon512Verifier::verify(msg(), array![].span(), array![].span()));
}
