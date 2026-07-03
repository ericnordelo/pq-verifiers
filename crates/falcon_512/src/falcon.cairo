// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT
//
// Hint-based verification equation from s2morrow `packages/falcon/src/falcon.cairo`
// (feltroidprime/s2morrow@4eff9ab9f5a4 `verify_with_msg_point`), reimplemented as a plain
// loop over the looped NTT (upstream is 8-way unrolled over the unrolled NTT) and returning
// `false` instead of panicking on a bad hint. `SIG_BOUND_512` matches falcon.py
// `params[512].sig_bound` and the starkware-bitcoin fork's `sig_bound(512)`.

//! Falcon-512 signature verification (hint-based variant).
//!
//! Verifies `s1 * h == mul_hint` via two forward NTTs and a pointwise product check
//! (the NTT is a bijection, so the check binds `mul_hint` to exactly `s1 * h mod (q, phi)`),
//! then accepts iff `||msg_point - mul_hint||^2 + ||s1||^2 <= SIG_BOUND_512` over centered
//! representatives. Since `msg_point - s1*h = s0`, this is the Falcon verification equation
//! with the polynomial multiplication delegated to a signer-supplied hint: 2 NTTs instead
//! of the 3 transforms of the direct method.

use crate::ntt::{intt, mul_ntt, ntt};
use crate::zq::{center_sq, mul_mod, sub_mod};

/// Maximum allowed `||s0||^2 + ||s1||^2` for Falcon-512 (FIPS 206 / falcon.py sig_bound).
pub const SIG_BOUND_512: u64 = 34034726;

/// Verify with a signer-supplied product hint. All spans must have length 512 and
/// coefficients in `[0, Q)` — guaranteed by `packing::unpack_512` and
/// `hash_to_point::hash_to_point_512`.
pub fn verify_512_with_hint(
    s1: Span<u16>, h_ntt: Span<u16>, mul_hint: Span<u16>, msg_point: Span<u16>,
) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(mul_hint.len() == 512, 'mul_hint must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let mut s1_ntt = ntt(s1);
    let mut hint_ntt = ntt(mul_hint);

    let mut h_iter = h_ntt;
    let mut msg_iter = msg_point;
    let mut hint_iter = mul_hint;
    let mut s1_iter = s1;

    // Fused pass: hint check and centered-norm accumulation per coefficient.
    // Max acc = 512 * 2 * 6144^2 < 2^36, so the felt252 accumulator cannot wrap
    // and always fits u64.
    let mut acc: felt252 = 0;
    let mut ok = true;
    while let Some(s1n) = s1_ntt.pop_front() {
        let hn = *hint_ntt.pop_front().unwrap();
        let h = *h_iter.pop_front().unwrap();
        if mul_mod(*s1n, h) != hn {
            ok = false;
            break;
        }
        let msg = *msg_iter.pop_front().unwrap();
        let hint = *hint_iter.pop_front().unwrap();
        let s1v = *s1_iter.pop_front().unwrap();
        acc += center_sq(sub_mod(msg, hint)) + center_sq(s1v);
    }
    if !ok {
        return false;
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

/// Verify without a hint (direct variant): compute `s1 * h` on-chain as
/// `INTT(NTT(s1) ∘ h_ntt)` — 1 NTT + 1 INTT because the public key is already stored in
/// the NTT domain — then accept iff `||msg_point - s1*h||^2 + ||s1||^2 <= SIG_BOUND_512`.
/// Same trust surface as the textbook equation (no signer-supplied hint), 29 fewer
/// signature felts than [`verify_512_with_hint`], at the cost of the INTT.
pub fn verify_512_direct(s1: Span<u16>, h_ntt: Span<u16>, msg_point: Span<u16>) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let s1_ntt = ntt(s1);
    let prod_ntt = mul_ntt(s1_ntt, h_ntt);
    let mut s1h = intt(prod_ntt);

    let mut msg_iter = msg_point;
    let mut s1_iter = s1;
    // Same accumulator bound argument as in `verify_512_with_hint`.
    let mut acc: felt252 = 0;
    while let Some(prod) = s1h.pop_front() {
        let msg = *msg_iter.pop_front().unwrap();
        let s1v = *s1_iter.pop_front().unwrap();
        acc += center_sq(sub_mod(msg, *prod)) + center_sq(s1v);
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

#[cfg(test)]
mod tests {
    use crate::ntt::{mul_zq, ntt};
    use crate::zq::add_mod;
    use super::{verify_512_direct, verify_512_with_hint};

    fn pseudorandom_coeffs(seed: u64) -> Array<u16> {
        let mut f: Array<u16> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            f.append((state % 12289).try_into().unwrap());
        }
        f
    }

    fn small_coeffs(seed: u64) -> Array<u16> {
        // Centered coefficients in [-16, 16]: comfortably inside the norm bound.
        let mut f: Array<u16> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            let centered = (state % 33).try_into().unwrap();
            if centered <= 16_u16 {
                f.append(centered);
            } else {
                f.append(12289 - (centered - 16));
            }
        }
        f
    }

    // Synthetic instance built from the verification equation itself: pick small s1 and
    // small s0, any h, set mul_hint = s1*h and msg_point = s0 + s1*h. A correct verifier
    // must accept it, and reject once the hint or the norm side is broken.
    #[test]
    fn test_verify_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span());
        let mul_hint = mul_zq(s1.span(), h.span());
        let mut msg_point: Array<u16> = array![];
        let mut s0_iter = s0.span();
        let mut prod_iter = mul_hint;
        while let Some(a) = s0_iter.pop_front() {
            msg_point.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        assert!(verify_512_with_hint(s1.span(), h_ntt, mul_hint, msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_bad_hint() {
        let s1 = small_coeffs(1);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span());
        let mut bad_hint = mul_zq(s1.span(), h.span());
        // Flip one coefficient of the hint.
        let first = *bad_hint.pop_front().unwrap();
        let mut tampered: Array<u16> = array![(first + 1) % 12289];
        while let Some(c) = bad_hint.pop_front() {
            tampered.append(*c);
        }
        // msg_point = mul_hint would give norm ||s1||^2 only — accepted if hint passed.
        let msg_point = mul_zq(s1.span(), h.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt, tampered.span(), msg_point));
    }

    // The direct variant must agree with the hint variant on the same instances.
    #[test]
    fn test_verify_direct_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span());
        let prod = mul_zq(s1.span(), h.span());
        let mut msg_point: Array<u16> = array![];
        let mut s0_iter = s0.span();
        let mut prod_iter = prod;
        while let Some(a) = s0_iter.pop_front() {
            msg_point.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        assert!(verify_512_direct(s1.span(), h_ntt, msg_point.span()));
        // Perturb one msg_point coefficient far from the lattice point: norm blows up.
        let mut bad_msg: Array<u16> = array![add_mod(*msg_point.span().at(0), 6144)];
        let mut rest = msg_point.span().slice(1, 511);
        while let Some(c) = rest.pop_front() {
            bad_msg.append(*c);
        }
        assert!(!verify_512_direct(s1.span(), h_ntt, bad_msg.span()));
    }

    #[test]
    fn test_verify_direct_rejects_large_norm() {
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span());
        // msg_point = s1*h so s0 = 0; ||s1||^2 alone is far above the bound.
        let msg_point = mul_zq(s1.span(), h.span());
        assert!(!verify_512_direct(s1.span(), h_ntt, msg_point));
    }

    #[test]
    fn test_verify_rejects_large_norm() {
        // s1 uniformly random in [0, Q): astronomically above the centered-norm bound,
        // with a consistent hint and msg_point = s1*h (so s0 = 0).
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span());
        let mul_hint = mul_zq(s1.span(), h.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt, mul_hint, mul_hint));
    }
}
