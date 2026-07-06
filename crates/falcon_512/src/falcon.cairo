//! Falcon-512 signature verification.
//!
//! Hint variant: verifies `s1 * h == mul_hint` via two forward NTTs and a pointwise
//! product check (the NTT is a bijection, so the check binds `mul_hint` to exactly
//! `s1 * h mod (q, phi)`), then accepts iff
//! `||msg_point - mul_hint||^2 + ||s1||^2 <= SIG_BOUND_512` over centered
//! representatives. Since `msg_point - s1*h = s0`, this is the Falcon verification
//! equation with the polynomial multiplication delegated to a signer-supplied hint;
//! a bad hint yields `false`. Both transforms are taken unreduced (the engine's
//! [`ntt_lazy`] entry point), and the pointwise check is a divisibility test on
//! `s1n*h + off - hn` — congruences mod q hold regardless of the reduction, so no
//! reduction pass is ever paid on the NTT outputs.
//!
//! Direct variant: computes `s1 * h` on-chain as `INTT(NTT(s1) ∘ h_ntt)` — the
//! unreduced transform's pointwise products feed the INTT directly (the engine's
//! lazy-product path).
//!
//! Coefficient spans arrive as felts in `[0, Q)` (the form `packing::unpack_512`
//! validates and the NTT engine consumes); the norm side downcasts them to `u16`
//! per coefficient.

use pqbench_ntt::engine::{intt, ntt_lazy};
use pqbench_ntt::falcon512::{Q_FELT, REDUCED_BITS, config};
use crate::zq::{center_sq, sub_mod};

/// Maximum allowed `||s0||^2 + ||s1||^2` for Falcon-512 (FIPS 206 / falcon.py sig_bound).
pub const SIG_BOUND_512: u64 = 34034726;

/// The Falcon modulus as a u128 divisor.
const Q_NZ: NonZero<u128> = 12289;

/// Verify with a signer-supplied product hint. All spans must have length 512 with
/// coefficients in `[0, Q)` — guaranteed by `packing::unpack_512` and
/// `hash_to_point::hash_to_point_512`.
pub fn verify_512_with_hint(
    s1: Span<felt252>, h_ntt: Span<felt252>, mul_hint: Span<felt252>, msg_point: Span<u16>,
) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(mul_hint.len() == 512, 'mul_hint must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let cfg = config();
    let (s1_ntt, _, bound) = ntt_lazy(s1, @cfg);
    let (hint_ntt, _, _) = ntt_lazy(mul_hint, @cfg);
    // A multiple of q dominating the lazy hn (< bound), so the divisibility operand
    // stays non-negative; s1n*h + off < 2·bound·q < 2^43 always fits u128.
    let off = bound * Q_FELT;

    let mut s1_ntt_iter = s1_ntt.span();
    let mut hint_ntt_iter = hint_ntt.span();
    let mut h_iter = h_ntt;
    let mut msg_iter = msg_point;
    let mut hint_iter = mul_hint;
    let mut s1_iter = s1;

    // Fused pass, 4-way unrolled (512 = 4 * 128, no remainder): hint check and
    // centered-norm accumulation per coefficient.
    // Max acc = 512 * 2 * 6144^2 < 2^36, so the felt252 accumulator cannot wrap
    // and always fits u64.
    let mut acc: felt252 = 0;
    let mut ok = true;
    while let Some(s1n_c) = s1_ntt_iter.multi_pop_front::<4>() {
        let [s1n0, s1n1, s1n2, s1n3] = (*s1n_c).unbox();
        let [hn0, hn1, hn2, hn3] = (*hint_ntt_iter.multi_pop_front::<4>().unwrap()).unbox();
        let [h0, h1, h2, h3] = (*h_iter.multi_pop_front::<4>().unwrap()).unbox();
        // s1n*h + off - hn ≡ s1n*h - hn (mod q): a zero remainder iff the two NTT
        // coordinates agree mod q, which by bijectivity binds mul_hint to s1*h.
        let d0: u128 = (s1n0 * h0 + off - hn0).try_into().unwrap();
        let (_, r0) = DivRem::div_rem(d0, Q_NZ);
        let d1: u128 = (s1n1 * h1 + off - hn1).try_into().unwrap();
        let (_, r1) = DivRem::div_rem(d1, Q_NZ);
        let d2: u128 = (s1n2 * h2 + off - hn2).try_into().unwrap();
        let (_, r2) = DivRem::div_rem(d2, Q_NZ);
        let d3: u128 = (s1n3 * h3 + off - hn3).try_into().unwrap();
        let (_, r3) = DivRem::div_rem(d3, Q_NZ);
        // Remainders are non-negative, so the sum is zero iff all four are.
        if r0 + r1 + r2 + r3 != 0 {
            ok = false;
            break;
        }
        let [m0, m1, m2, m3] = (*msg_iter.multi_pop_front::<4>().unwrap()).unbox();
        let [t0, t1, t2, t3] = (*hint_iter.multi_pop_front::<4>().unwrap()).unbox();
        let [v0, v1, v2, v3] = (*s1_iter.multi_pop_front::<4>().unwrap()).unbox();
        // Unpacked coefficients are < q, so the u16 downcasts never fail.
        acc += center_sq(sub_mod(m0, t0.try_into().unwrap())) + center_sq(v0.try_into().unwrap());
        acc += center_sq(sub_mod(m1, t1.try_into().unwrap())) + center_sq(v1.try_into().unwrap());
        acc += center_sq(sub_mod(m2, t2.try_into().unwrap())) + center_sq(v2.try_into().unwrap());
        acc += center_sq(sub_mod(m3, t3.try_into().unwrap())) + center_sq(v3.try_into().unwrap());
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
pub fn verify_512_direct(s1: Span<felt252>, h_ntt: Span<felt252>, msg_point: Span<u16>) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let cfg = config();
    let (s1_ntt, bits, bound) = ntt_lazy(s1, @cfg);

    // Pointwise products of the unreduced transform against the reduced key,
    // UNREDUCED (< bound·q): the engine's lazy-product INTT path reduces them for
    // free inside its bound schedule.
    let mut prods: Array<felt252> = array![];
    let mut s1n_iter = s1_ntt.span();
    let mut h_iter = h_ntt;
    while let Some(s1n) = s1n_iter.pop_front() {
        prods.append(*s1n * *h_iter.pop_front().unwrap());
    }
    let s1h = intt(prods.span(), bits + REDUCED_BITS, bound * Q_FELT, @cfg);

    let mut s1h_iter = s1h.span();
    let mut msg_iter = msg_point;
    let mut s1_iter = s1;
    // Norm pass, 4-way unrolled (512 = 4 * 128, no remainder).
    // Same accumulator bound argument as in `verify_512_with_hint`.
    let mut acc: felt252 = 0;
    while let Some(pc) = s1h_iter.multi_pop_front::<4>() {
        let [p0, p1, p2, p3] = (*pc).unbox();
        let [m0, m1, m2, m3] = (*msg_iter.multi_pop_front::<4>().unwrap()).unbox();
        let [v0, v1, v2, v3] = (*s1_iter.multi_pop_front::<4>().unwrap()).unbox();
        // INTT outputs are reduced and s1 coefficients unpacked canonical, both < q,
        // so the u16 downcasts never fail.
        acc += center_sq(sub_mod(m0, p0.try_into().unwrap())) + center_sq(v0.try_into().unwrap());
        acc += center_sq(sub_mod(m1, p1.try_into().unwrap())) + center_sq(v1.try_into().unwrap());
        acc += center_sq(sub_mod(m2, p2.try_into().unwrap())) + center_sq(v2.try_into().unwrap());
        acc += center_sq(sub_mod(m3, p3.try_into().unwrap())) + center_sq(v3.try_into().unwrap());
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

#[cfg(test)]
mod tests {
    use pqbench_ntt::engine::{intt, ntt};
    use pqbench_ntt::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
    use crate::zq::add_mod;
    use super::{verify_512_direct, verify_512_with_hint};

    fn to_u16(mut vals: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        while let Some(v) = vals.pop_front() {
            out.append((*v).try_into().unwrap());
        }
        out
    }

    /// Negacyclic product in Z_q[x]/(x^512 + 1) (test helper).
    fn mul_zq(f: Span<felt252>, g: Span<felt252>) -> Array<felt252> {
        let cfg = config();
        let f_ntt = ntt(f, @cfg);
        let g_ntt = ntt(g, @cfg);
        let mut prods: Array<felt252> = array![];
        let mut fi = f_ntt.span();
        let mut gi = g_ntt.span();
        while let Some(a) = fi.pop_front() {
            prods.append(*a * *gi.pop_front().unwrap());
        }
        intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg)
    }

    fn pseudorandom_coeffs(seed: u64) -> Array<felt252> {
        let mut f: Array<felt252> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            f.append((state % 12289).into());
        }
        f
    }

    fn small_coeffs(seed: u64) -> Array<felt252> {
        // Centered coefficients in [-16, 16]: comfortably inside the norm bound.
        let mut f: Array<felt252> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            let centered = state % 33;
            if centered <= 16 {
                f.append(centered.into());
            } else {
                f.append((12289 - (centered - 16)).into());
            }
        }
        f
    }

    /// msg_point = s0 + prod coefficient-wise, downcast to the norm side's u16 form.
    fn add_points(s0: Span<felt252>, prod: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        let mut s0_iter = to_u16(s0).span();
        let mut prod_iter = to_u16(prod).span();
        while let Some(a) = s0_iter.pop_front() {
            out.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        out
    }

    // Synthetic instance built from the verification equation itself: pick small s1 and
    // small s0, any h, set mul_hint = s1*h and msg_point = s0 + s1*h. A correct verifier
    // must accept it, and reject once the hint or the norm side is broken.
    #[test]
    fn test_verify_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let mul_hint = mul_zq(s1.span(), h.span());
        let msg_point = add_points(s0.span(), mul_hint.span());
        assert!(verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_bad_hint() {
        let s1 = small_coeffs(1);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let good_hint = mul_zq(s1.span(), h.span());
        // Flip one coefficient of the hint.
        let mut hint_iter = good_hint.span();
        let first: u16 = (*hint_iter.pop_front().unwrap()).try_into().unwrap();
        let mut tampered: Array<felt252> = array![((first + 1) % 12289).into()];
        while let Some(c) = hint_iter.pop_front() {
            tampered.append(*c);
        }
        // msg_point = mul_hint would give norm ||s1||^2 only — accepted if hint passed.
        let msg_point = to_u16(mul_zq(s1.span(), h.span()).span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), tampered.span(), msg_point.span()));
    }

    // The direct variant must agree with the hint variant on the same instances.
    #[test]
    fn test_verify_direct_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let prod = mul_zq(s1.span(), h.span());
        let msg_point = add_points(s0.span(), prod.span());
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
        let h_ntt = ntt(h.span(), @config());
        // msg_point = s1*h so s0 = 0; ||s1||^2 alone is far above the bound.
        let msg_point = to_u16(mul_zq(s1.span(), h.span()).span());
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_large_norm() {
        // s1 uniformly random in [0, Q): astronomically above the centered-norm bound,
        // with a consistent hint and msg_point = s1*h (so s0 = 0).
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let mul_hint = mul_zq(s1.span(), h.span());
        let msg_point = to_u16(mul_hint.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }
}
