//! Falcon-512 (FN-DSA) signature verifier — direct-NTT variant.
//!
//! On-chain cost is the integer part of Falcon verification; the SHAKE-256
//! hash-to-point is computed off-chain and its result (`msg_point`) is carried in
//! the signature (the s2morrow interop path). Given the public key `h` and a
//! signature `(s2, msg_point)`, verification recovers `s1 = msg_point - s2*h`
//! (mod q, via the NTT) and accepts iff the squared norm is within bound.
//!
//! Encoding (base-Q, 18 coeffs/felt, 29 felts each):
//! - `public_key` (29 felts): `h`, the public polynomial (coefficient domain).
//! - `signature`  (58 felts): `pack(s2)` (29) ++ `pack(msg_point)` (29).
//!
//! The looped NTT/`mul_zq` is ported from s2morrow (StarkWare Industries, MIT);
//! see PORTING.md. `mul_zq` makes the product convention-independent, so the
//! off-chain fixture needs no NTT-convention matching.

use pqbench_interface::PqSignatureVerifier;

pub mod zq;
pub mod ntt_constants;
pub mod ntt;
pub mod packing;

use ntt::{mul_zq, sub_zq};
use packing::unpack_512;

/// Falcon-512 squared L2 acceptance bound (l2bound[9]).
const SIG_BOUND_512: u64 = 34_034_726;

/// |center(x)|^2 for x in [0, q): map to [-q/2, q/2], return the square.
fn center_sq(x: u16) -> u64 {
    let c: u64 = if x > 6144 {
        (12289 - x).into()
    } else {
        x.into()
    };
    c * c
}

pub impl Falcon512Verifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let _ = message_hash; // hash-to-point is off-chain; msg_point is in the signature
        if public_key.len() != 29 || signature.len() != 58 {
            return false;
        }
        let h = unpack_512(public_key);
        let s2 = unpack_512(signature.slice(0, 29));
        let msg_point = unpack_512(signature.slice(29, 29));

        // s1 = msg_point - s2*h   (s2*h via NTT, convention-independent)
        let s2h = mul_zq(s2.span(), h.span());
        let s1 = sub_zq(msg_point.span(), s2h);

        // accept iff ||s1||^2 + ||s2||^2 <= bound (centered coefficients)
        let mut acc: u64 = 0;
        let mut i: u32 = 0;
        while i != 512 {
            acc += center_sq(*s1.at(i)) + center_sq(*s2.at(i));
            i += 1;
        }
        acc <= SIG_BOUND_512
    }
}
