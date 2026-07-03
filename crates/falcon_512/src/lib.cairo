//! Falcon-512 (FN-DSA) signature verifiers: two verification variants x two on-chain
//! hash-to-point constructions = four registered schemes.
//!
//! Ported from s2morrow (MIT; see per-module headers and `PORTING.md` for provenance and
//! deviations). All schemes share the NTT-domain 29-felt public key, the validating
//! base-Q unpack, the looped NTT/INTT, and the Falcon-512 norm bound; they differ in:
//!
//! - **verification**: *hint* (60-felt signature carrying `mul_hint = s1*h`; two forward
//!   NTTs bind the hint) vs *direct* (31-felt signature; `s1*h = INTT(NTT(s1) ∘ h_ntt)`);
//! - **hash-to-point** (both NON-standard — FIPS 206 uses SHAKE-256): *BLAKE2s*
//!   counter-mode XOF with spec rejection sampling (`hash_to_point.cairo`) vs *Poseidon*
//!   sponge squeeze as deployed by s2morrow (`hash_to_point_poseidon.cairo`).
//!
//! Verification runs entirely on-chain: the message point is derived from `message_hash`
//! and the signature salt, so signatures are bound to the message. All parsing is
//! validating; `verify` returns `false` on any malformed input.
//!
//! Fixture generation for tests/benchmarks: `scripts/gen_falcon_fixture.py`.

pub mod bench_fixture;
pub mod bench_fixture_poseidon;
pub mod falcon;
pub mod hash_to_point;
pub mod hash_to_point_poseidon;
pub mod ntt;
pub mod ntt_constants;
pub mod packing;
pub mod zq;

use pqbench_interface::PqSignatureVerifier;

/// Hint-variant signature layout: packed s1 (29 felts) || salt (2 felts, 20 LE bytes
/// each) || packed mul_hint = s1*h mod (q, x^512+1) (29 felts).
pub const SIG_FELTS: u32 = 60;
/// Direct-variant signature layout: packed s1 (29 felts) || salt (2 felts) — a prefix
/// of the hint-variant layout, so one signer output serves both schemes.
pub const SIG_FELTS_DIRECT: u32 = 31;
/// Public key layout: packed NTT-domain h (29 felts). Enforced by `unpack_512`.
pub const PUBKEY_FELTS: u32 = 29;

/// Layout-validated inputs shared by every variant: unpacked public key and s1
/// (canonical coefficients in [0, Q)), plus the raw salt felts.
#[derive(Drop)]
struct ParsedCommon {
    h_ntt: Array<u16>,
    s1: Array<u16>,
    salt_a: felt252,
    salt_b: felt252,
}

/// Parse the public key and the common `s1 || salt` signature prefix.
/// `unpack_512` rejects a public key that is not exactly 29 canonical felts.
/// Callers must have checked `signature.len()` (slice panics on short spans).
fn parse_common(public_key: Span<felt252>, signature: Span<felt252>) -> Option<ParsedCommon> {
    let h_ntt = packing::unpack_512(public_key)?;
    let s1 = packing::unpack_512(signature.slice(0, 29))?;
    Some(ParsedCommon { h_ntt, s1, salt_a: *signature.at(29), salt_b: *signature.at(30) })
}

/// Parse the 31-felt direct layout.
fn parse_direct(public_key: Span<felt252>, signature: Span<felt252>) -> Option<ParsedCommon> {
    if signature.len() != SIG_FELTS_DIRECT {
        return None;
    }
    parse_common(public_key, signature)
}

/// Parse the 60-felt hint layout: the common prefix plus the unpacked mul hint.
fn parse_hint(
    public_key: Span<felt252>, signature: Span<felt252>,
) -> Option<(ParsedCommon, Array<u16>)> {
    if signature.len() != SIG_FELTS {
        return None;
    }
    let common = parse_common(public_key, signature)?;
    let mul_hint = packing::unpack_512(signature.slice(31, 29))?;
    Some((common, mul_hint))
}

/// Hint variant, BLAKE2s hash-to-point (scheme `falcon_512`).
pub impl Falcon512Verifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let (common, mul_hint) = match parse_hint(public_key, signature) {
            Some(v) => v,
            None => { return false; },
        };
        let msg_point =
            match hash_to_point::hash_to_point_512(message_hash, common.salt_a, common.salt_b) {
                Some(v) => v,
                None => { return false; },
            };
        falcon::verify_512_with_hint(
            common.s1.span(), common.h_ntt.span(), mul_hint.span(), msg_point.span(),
        )
    }
}

/// Direct variant, BLAKE2s hash-to-point (scheme `falcon_512_direct`).
pub impl Falcon512DirectVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let common = match parse_direct(public_key, signature) {
            Some(v) => v,
            None => { return false; },
        };
        let msg_point =
            match hash_to_point::hash_to_point_512(message_hash, common.salt_a, common.salt_b) {
                Some(v) => v,
                None => { return false; },
            };
        falcon::verify_512_direct(common.s1.span(), common.h_ntt.span(), msg_point.span())
    }
}

/// Hint variant, Poseidon hash-to-point (scheme `falcon_512_poseidon`).
pub impl Falcon512PoseidonVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let (common, mul_hint) = match parse_hint(public_key, signature) {
            Some(v) => v,
            None => { return false; },
        };
        let msg_point =
            match hash_to_point_poseidon::hash_to_point_poseidon_512(
                message_hash, common.salt_a, common.salt_b,
            ) {
                Some(v) => v,
                None => { return false; },
            };
        falcon::verify_512_with_hint(
            common.s1.span(), common.h_ntt.span(), mul_hint.span(), msg_point.span(),
        )
    }
}

/// Direct variant, Poseidon hash-to-point (scheme `falcon_512_poseidon_direct`).
pub impl Falcon512PoseidonDirectVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let common = match parse_direct(public_key, signature) {
            Some(v) => v,
            None => { return false; },
        };
        let msg_point =
            match hash_to_point_poseidon::hash_to_point_poseidon_512(
                message_hash, common.salt_a, common.salt_b,
            ) {
                Some(v) => v,
                None => { return false; },
            };
        falcon::verify_512_direct(common.s1.span(), common.h_ntt.span(), msg_point.span())
    }
}
