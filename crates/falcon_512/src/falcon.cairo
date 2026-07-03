//! Falcon-512 signature verification.
//!
//! Hint variant: verifies `s1 * h == mul_hint` via two forward NTTs and a pointwise
//! product check (the NTT is a bijection, so the check binds `mul_hint` to exactly
//! `s1 * h mod (q, phi)`), then accepts iff
//! `||msg_point - mul_hint||^2 + ||s1||^2 <= SIG_BOUND_512` over centered
//! representatives. Since `msg_point - s1*h = s0`, this is the Falcon verification
//! equation with the polynomial multiplication delegated to a signer-supplied hint;
//! a bad hint yields `false`.
//!
//! Direct variant: computes `s1 * h` on-chain as `INTT(NTT(s1) ∘ h_ntt)` — the
//! pointwise products feed the INTT unreduced (the engine's lazy-product path).

use pqbench_ntt::engine::{intt, ntt, reduce_felt};
use pqbench_ntt::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
use crate::zq::{center_sq, sub_mod};

/// Maximum allowed `||s0||^2 + ||s1||^2` for Falcon-512 (FIPS 206 / falcon.py sig_bound).
pub const SIG_BOUND_512: u64 = 34034726;

/// The Falcon modulus as a u128 divisor.
const Q_NZ: NonZero<u128> = 12289;

/// Upcast a coefficient span for the engine.
pub fn to_felts(mut vals: Span<u16>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    while let Some(v) = vals.pop_front() {
        out.append((*v).into());
    }
    out
}

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

    let cfg = config();
    let s1_ntt = ntt(to_felts(s1).span(), @cfg);
    let hint_ntt = ntt(to_felts(mul_hint).span(), @cfg);

    let mut s1_ntt_iter = s1_ntt.span();
    let mut hint_ntt_iter = hint_ntt.span();
    let mut h_iter = h_ntt;
    let mut msg_iter = msg_point;
    let mut hint_iter = mul_hint;
    let mut s1_iter = s1;

    // Fused pass: hint check and centered-norm accumulation per coefficient.
    // Max acc = 512 * 2 * 6144^2 < 2^36, so the felt252 accumulator cannot wrap
    // and always fits u64.
    let mut acc: felt252 = 0;
    let mut ok = true;
    while let Some(s1n) = s1_ntt_iter.pop_front() {
        let hn = *hint_ntt_iter.pop_front().unwrap();
        let h: felt252 = (*h_iter.pop_front().unwrap()).into();
        // s1n, h < q, so the product is < q^2 < 2^28 and reduces through u128.
        if reduce_felt(*s1n * h, Q_NZ) != hn {
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

    let cfg = config();
    let s1_ntt = ntt(to_felts(s1).span(), @cfg);

    // Pointwise products, UNREDUCED (< q^2): the engine's lazy-product INTT path
    // reduces them for free inside its bound schedule.
    let mut prods: Array<felt252> = array![];
    let mut s1n_iter = s1_ntt.span();
    let mut h_iter = h_ntt;
    while let Some(s1n) = s1n_iter.pop_front() {
        let h: felt252 = (*h_iter.pop_front().unwrap()).into();
        prods.append(*s1n * h);
    }
    let s1h = intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg);

    let mut s1h_iter = s1h.span();
    let mut msg_iter = msg_point;
    let mut s1_iter = s1;
    // Same accumulator bound argument as in `verify_512_with_hint`.
    let mut acc: felt252 = 0;
    while let Some(prod) = s1h_iter.pop_front() {
        // INTT outputs are reduced to [0, q), so the downcast never fails.
        let p: u16 = (*prod).try_into().unwrap();
        let msg = *msg_iter.pop_front().unwrap();
        let s1v = *s1_iter.pop_front().unwrap();
        acc += center_sq(sub_mod(msg, p)) + center_sq(s1v);
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

#[cfg(test)]
mod tests {
    use pqbench_ntt::engine::{intt, ntt};
    use pqbench_ntt::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
    use crate::zq::add_mod;
    use super::{to_felts, verify_512_direct, verify_512_with_hint};

    fn to_u16(mut vals: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        while let Some(v) = vals.pop_front() {
            out.append((*v).try_into().unwrap());
        }
        out
    }

    /// Forward NTT over u16 coefficients (test helper).
    fn ntt_u16(f: Span<u16>) -> Array<u16> {
        let cfg = config();
        to_u16(ntt(to_felts(f).span(), @cfg).span())
    }

    /// Negacyclic product in Z_q[x]/(x^512 + 1) (test helper).
    fn mul_zq(f: Span<u16>, g: Span<u16>) -> Array<u16> {
        let cfg = config();
        let f_ntt = ntt(to_felts(f).span(), @cfg);
        let g_ntt = ntt(to_felts(g).span(), @cfg);
        let mut prods: Array<felt252> = array![];
        let mut fi = f_ntt.span();
        let mut gi = g_ntt.span();
        while let Some(a) = fi.pop_front() {
            prods.append(*a * *gi.pop_front().unwrap());
        }
        to_u16(intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg).span())
    }

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
        let h_ntt = ntt_u16(h.span());
        let mul_hint = mul_zq(s1.span(), h.span());
        let mut msg_point: Array<u16> = array![];
        let mut s0_iter = s0.span();
        let mut prod_iter = mul_hint.span();
        while let Some(a) = s0_iter.pop_front() {
            msg_point.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        assert!(verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_bad_hint() {
        let s1 = small_coeffs(1);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt_u16(h.span());
        let good_hint = mul_zq(s1.span(), h.span());
        // Flip one coefficient of the hint.
        let mut hint_iter = good_hint.span();
        let first = *hint_iter.pop_front().unwrap();
        let mut tampered: Array<u16> = array![(first + 1) % 12289];
        while let Some(c) = hint_iter.pop_front() {
            tampered.append(*c);
        }
        // msg_point = mul_hint would give norm ||s1||^2 only — accepted if hint passed.
        let msg_point = mul_zq(s1.span(), h.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), tampered.span(), msg_point.span()));
    }

    // The direct variant must agree with the hint variant on the same instances.
    #[test]
    fn test_verify_direct_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt_u16(h.span());
        let prod = mul_zq(s1.span(), h.span());
        let mut msg_point: Array<u16> = array![];
        let mut s0_iter = s0.span();
        let mut prod_iter = prod.span();
        while let Some(a) = s0_iter.pop_front() {
            msg_point.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        assert!(verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
        // Perturb one msg_point coefficient far from the lattice point: norm blows up.
        let mut bad_msg: Array<u16> = array![add_mod(*msg_point.span().at(0), 6144)];
        let mut rest = msg_point.span().slice(1, 511);
        while let Some(c) = rest.pop_front() {
            bad_msg.append(*c);
        }
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), bad_msg.span()));
    }

    #[test]
    fn test_verify_direct_rejects_large_norm() {
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt_u16(h.span());
        // msg_point = s1*h so s0 = 0; ||s1||^2 alone is far above the bound.
        let msg_point = mul_zq(s1.span(), h.span());
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_large_norm() {
        // s1 uniformly random in [0, Q): astronomically above the centered-norm bound,
        // with a consistent hint and msg_point = s1*h (so s0 = 0).
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt_u16(h.span());
        let mul_hint = mul_zq(s1.span(), h.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), mul_hint.span()));
    }
}
