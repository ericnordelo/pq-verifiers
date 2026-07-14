//! Correctness gate for the iterative lazy-reduction engine.
//!
//! Strategy: a test-local RECURSIVE ORACLE computes the tprest/falcon.py split/merge NTT
//! directly (eager u16 arithmetic over the same root tables). The falcon.py known-answer
//! vectors pin the oracle to the interop convention; differential tests then pin the
//! engine to the oracle on every size, on pseudorandom and adversarial inputs.
//! `scripts/gen_ntt_tables.py` carries the same argument in Python, including the
//! bound-growth safety proof.

use pqbench_ntt::engine::{intt, ntt, ntt_lazy};
use pqbench_ntt::falcon512::{
    PRODUCT_BITS, PRODUCT_BOUND_FELT, Q, REDUCED_BITS, config, config_for_degree,
};
use pqbench_ntt::roots::{get_even_roots, get_even_roots_inv};
use pqbench_ntt::{ntt_falcon512_fast_u16_unchecked, ntt_falcon512_fast_unchecked};

// --- Recursive oracle (test-local reference implementation) ---

const I2: u16 = 6145;
const SQR1: u16 = 1479;
const SQR1_INV: u16 = 10810;

fn add_mod(a: u16, b: u16) -> u16 {
    (a + b) % Q
}

fn sub_mod(a: u16, b: u16) -> u16 {
    (a + Q - b) % Q
}

fn mul_mod(a: u16, b: u16) -> u16 {
    let a: u32 = a.into();
    let b: u32 = b.into();
    ((a * b) % 12289_u32).try_into().unwrap()
}

fn mul3_mod(a: u16, b: u16, c: u16) -> u16 {
    let a: u64 = a.into();
    let b: u64 = b.into();
    let c: u64 = c.into();
    ((a * b * c) % 12289_u64).try_into().unwrap()
}

fn split(mut f: Span<u16>) -> (Span<u16>, Span<u16>) {
    let mut f0 = array![];
    let mut f1 = array![];
    while let Some(even) = f.pop_front() {
        let odd = f.pop_front().unwrap();
        f0.append(*even);
        f1.append(*odd);
    }
    (f0.span(), f1.span())
}

fn merge(mut f0: Span<u16>, mut f1: Span<u16>) -> Span<u16> {
    let mut f = array![];
    while let Some(a) = f0.pop_front() {
        let b = f1.pop_front().unwrap();
        f.append(*a);
        f.append(*b);
    }
    f.span()
}

fn oracle_ntt(f: Span<u16>) -> Span<u16> {
    let n = f.len();
    if n == 2 {
        let t = mul_mod(SQR1, *f[1]);
        return array![add_mod(*f[0], t), sub_mod(*f[0], t)].span();
    }
    let (f0, f1) = split(f);
    let f0_ntt = oracle_ntt(f0);
    let mut f1_ntt = oracle_ntt(f1);
    let mut roots = get_even_roots(n);
    let mut f0_iter = f0_ntt;
    let mut out = array![];
    while let Some(root) = roots.pop_front() {
        let a = *f0_iter.pop_front().unwrap();
        let b = *f1_ntt.pop_front().unwrap();
        let t = mul_mod(*root, b);
        out.append(add_mod(a, t));
        out.append(sub_mod(a, t));
    }
    out.span()
}

fn oracle_intt(f_ntt: Span<u16>) -> Span<u16> {
    let n = f_ntt.len();
    if n == 2 {
        let even = mul_mod(I2, add_mod(*f_ntt[0], *f_ntt[1]));
        let odd = mul3_mod(I2, sub_mod(*f_ntt[0], *f_ntt[1]), SQR1_INV);
        return array![even, odd].span();
    }
    let mut roots_inv = get_even_roots_inv(n);
    let mut src = f_ntt;
    let mut f0 = array![];
    let mut f1 = array![];
    while let Some(root_inv) = roots_inv.pop_front() {
        let even = *src.pop_front().unwrap();
        let odd = *src.pop_front().unwrap();
        f0.append(mul_mod(I2, add_mod(even, odd)));
        f1.append(mul3_mod(I2, sub_mod(even, odd), *root_inv));
    }
    merge(oracle_intt(f0.span()), oracle_intt(f1.span()))
}

// --- Helpers ---

fn to_felts(mut vals: Span<u16>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    while let Some(v) = vals.pop_front() {
        out.append((*v).into());
    }
    out
}

fn assert_felts_eq_u16(mut got: Span<felt252>, mut expect: Span<u16>) {
    assert_eq!(got.len(), expect.len());
    while let Some(g) = got.pop_front() {
        let e: felt252 = (*expect.pop_front().unwrap()).into();
        assert_eq!(*g, e);
    }
}

fn pseudorandom(seed: u64, n: u32) -> Array<u16> {
    let mut f: Array<u16> = array![];
    let mut state: u64 = seed;
    for _ in 0..n {
        state = (state * 1664525 + 1013904223) % 0x100000000;
        f.append((state % 12289).try_into().unwrap());
    }
    f
}

fn levels_of(n: u32) -> u32 {
    let mut levels = 0;
    let mut size = 1_u32;
    while size != n {
        size = 2 * size;
        levels += 1;
    }
    levels
}

// --- Known-answer tests: pin the oracle (and the engine) to falcon.py ---

#[test]
fn test_kat_4() {
    let f: Array<u16> = array![1, 2, 3, 4];
    let expect: Array<u16> = array![4229, 4647, 1973, 1444];
    assert_eq!(oracle_ntt(f.span()), expect.span());
    let cfg = config_for_degree(4, 2);
    assert_felts_eq_u16(ntt(to_felts(f.span()).span(), @cfg).span(), expect.span());
}

#[test]
fn test_kat_8() {
    let f: Array<u16> = array![1, 2, 3, 4, 5, 6, 7, 8];
    let expect: Array<u16> = array![6197, 9965, 404, 729, 2285, 6357, 1586, 9352];
    assert_eq!(oracle_ntt(f.span()), expect.span());
    let cfg = config_for_degree(8, 3);
    assert_felts_eq_u16(ntt(to_felts(f.span()).span(), @cfg).span(), expect.span());
}

#[test]
fn test_kat_16() {
    let f: Array<u16> = array![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let expect: Array<u16> = array![
        904, 11625, 1858, 11886, 2859, 7918, 10924, 9366, 10593, 81, 3208, 9897, 12204, 1340, 7546,
        8408,
    ];
    assert_eq!(oracle_ntt(f.span()), expect.span());
    let cfg = config_for_degree(16, 4);
    assert_felts_eq_u16(ntt(to_felts(f.span()).span(), @cfg).span(), expect.span());
}

/// The [1..512] ramp: first 8 outputs pinned to falcon.py (the vector
/// `scripts/verify_ntt_constants.py` cross-checks); the full vector is checked
/// differentially against the oracle.
#[test]
fn test_kat_512_prefix_and_differential() {
    let mut f: Array<u16> = array![];
    let mut i: u16 = 1;
    while i != 513 {
        f.append(i);
        i += 1;
    }
    let expect = oracle_ntt(f.span());
    assert_eq!(*expect.at(0), 5279);
    assert_eq!(*expect.at(1), 3373);
    assert_eq!(*expect.at(2), 4474);
    assert_eq!(*expect.at(3), 2755);
    assert_eq!(*expect.at(4), 3765);
    assert_eq!(*expect.at(5), 9923);
    assert_eq!(*expect.at(6), 3810);
    assert_eq!(*expect.at(7), 3849);

    let cfg = config();
    let got = ntt(to_felts(f.span()).span(), @cfg);
    assert_felts_eq_u16(got.span(), expect);

    let back = intt(got.span(), REDUCED_BITS, 12289, @cfg);
    assert_felts_eq_u16(back.span(), f.span());
}

// --- Differential tests: engine == oracle on every size ---

#[test]
fn test_differential_all_sizes() {
    let mut n: u32 = 4;
    while n != 1024 {
        let cfg = config_for_degree(n, levels_of(n));
        let mut seed: u64 = 7;
        while seed != 9 {
            let f = pseudorandom(seed * n.into(), n);
            let expect = oracle_ntt(f.span());
            let got = ntt(to_felts(f.span()).span(), @cfg);
            assert_felts_eq_u16(got.span(), expect);

            let back = intt(got.span(), REDUCED_BITS, 12289, @cfg);
            assert_felts_eq_u16(back.span(), f.span());
            seed += 1;
        }
        n = 2 * n;
    }
}

/// Worst case for lazy-reduction bound growth: every coefficient at q - 1.
#[test]
fn test_worst_case_all_q_minus_1() {
    let mut f: Array<u16> = array![];
    for _ in 0_u32..512 {
        f.append(Q - 1);
    }
    let cfg = config();
    let expect = oracle_ntt(f.span());
    let got = ntt(to_felts(f.span()).span(), @cfg);
    assert_felts_eq_u16(got.span(), expect);
    let back = intt(got.span(), REDUCED_BITS, 12289, @cfg);
    assert_felts_eq_u16(back.span(), f.span());
}

/// The production table-driven permutation and the computed one must agree.
#[test]
fn test_config_matches_config_for_degree() {
    let f = pseudorandom(42, 512);
    let table_cfg = config();
    let computed_cfg = config_for_degree(512, 9);
    let a = ntt(to_felts(f.span()).span(), @table_cfg);
    let b = ntt(to_felts(f.span()).span(), @computed_cfg);
    assert_eq!(a, b);
}

/// The generated fixed-parameter circuit must agree with the generic engine on
/// pseudorandom and worst-case canonical inputs.
#[test]
fn test_falcon512_fast_matches_generic() {
    let cfg = config();
    let mut seed: u64 = 19;
    while seed != 22 {
        let input_u16 = pseudorandom(seed, 512);
        let input = to_felts(input_u16.span());
        let expected = ntt(input.span(), @cfg);
        let got = ntt_falcon512_fast_unchecked(input.span());
        assert_eq!(got, expected);
        assert_felts_eq_u16(
            expected.span(), ntt_falcon512_fast_u16_unchecked(input_u16.span()).span(),
        );
        seed += 1;
    }

    let mut worst: Array<felt252> = array![];
    let mut worst_u16: Array<u16> = array![];
    for _ in 0_u32..512 {
        worst.append((Q - 1).into());
        worst_u16.append(Q - 1);
    }
    let expected = ntt(worst.span(), @cfg);
    assert_eq!(ntt_falcon512_fast_unchecked(worst.span()), expected);
    assert_felts_eq_u16(expected.span(), ntt_falcon512_fast_u16_unchecked(worst_u16.span()).span());
}

// --- The lazy-product path used by the direct Falcon variant ---

/// x · x^511 = x^512 ≡ -1 (mod x^512 + 1): NTT both factors, multiply pointwise WITHOUT
/// reducing, INTT with the product bound. Exercises the negacyclic wraparound and the
/// unreduced-input path end to end.
#[test]
fn test_negacyclic_wrap_lazy_products() {
    let cfg = config();
    let mut f: Array<felt252> = array![0, 1];
    let mut g: Array<felt252> = array![];
    for _ in 2_u32..512 {
        f.append(0);
    }
    for _ in 0_u32..511 {
        g.append(0);
    }
    g.append(1);

    let f_ntt = ntt(f.span(), @cfg);
    let g_ntt = ntt(g.span(), @cfg);
    let mut prods: Array<felt252> = array![];
    let mut fi = f_ntt.span();
    let mut gi = g_ntt.span();
    while let Some(a) = fi.pop_front() {
        prods.append(*a * *gi.pop_front().unwrap());
    }
    let mut res = intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg).span();
    let first: felt252 = (Q - 1).into();
    assert_eq!(*res.pop_front().unwrap(), first);
    while let Some(c) = res.pop_front() {
        assert_eq!(*c, 0);
    }
}

/// The unreduced forward transform must agree with [`ntt`] coefficient-wise mod q,
/// and every output must stay below the exact bound it reports.
#[test]
fn test_ntt_lazy_matches_reduced() {
    let q_nz: NonZero<u128> = 12289_u128.try_into().unwrap();
    let mut n: u32 = 4;
    while n != 1024 {
        let cfg = config_for_degree(n, levels_of(n));
        let f = to_felts(pseudorandom(11 * n.into(), n).span());
        let (lazy, bits, bound) = ntt_lazy(f.span(), @cfg);
        let expect = ntt(f.span(), @cfg);
        assert!(bits <= 126);
        let bound_u128: u128 = bound.try_into().unwrap();
        let mut li = lazy.span();
        let mut ei = expect.span();
        while let Some(v) = li.pop_front() {
            let vu: u128 = (*v).try_into().unwrap();
            assert!(vu < bound_u128);
            let (_, rem) = DivRem::div_rem(vu, q_nz);
            let e: felt252 = *ei.pop_front().unwrap();
            assert_eq!(Into::<u128, felt252>::into(rem), e);
        }
        n = 2 * n;
    }
}

/// Pointwise products of an unreduced transform against a reduced one, fed to the
/// INTT under the lazy bound (the direct Falcon variant's pipeline), must match the
/// fully reduced computation.
#[test]
fn test_ntt_lazy_product_pipeline() {
    let cfg = config();
    let a = to_felts(pseudorandom(5, 512).span());
    let b = to_felts(pseudorandom(6, 512).span());
    let (a_lazy, bits, bound) = ntt_lazy(a.span(), @cfg);
    let b_ntt = ntt(b.span(), @cfg);

    let mut lazy: Array<felt252> = array![];
    let mut reduced: Array<u16> = array![];
    let mut ai = a_lazy.span();
    let mut a_red = ntt(a.span(), @cfg).span();
    let mut bi = b_ntt.span();
    while let Some(x) = ai.pop_front() {
        let y = *bi.pop_front().unwrap();
        lazy.append(*x * y);
        let xu: u16 = (*a_red.pop_front().unwrap()).try_into().unwrap();
        let yu: u16 = y.try_into().unwrap();
        reduced.append(mul_mod(xu, yu));
    }
    let got = intt(lazy.span(), bits + REDUCED_BITS, bound * 12289, @cfg);
    let expect = oracle_intt(reduced.span());
    assert_felts_eq_u16(got.span(), expect);
}

/// Lazy-product INTT must agree with reducing the products first.
#[test]
fn test_lazy_products_match_reduced_products() {
    let cfg = config();
    let a = to_felts(pseudorandom(3, 512).span());
    let b = to_felts(pseudorandom(4, 512).span());
    let a_ntt = ntt(a.span(), @cfg);
    let b_ntt = ntt(b.span(), @cfg);

    let mut lazy: Array<felt252> = array![];
    let mut reduced: Array<u16> = array![];
    let mut ai = a_ntt.span();
    let mut bi = b_ntt.span();
    while let Some(x) = ai.pop_front() {
        let y = *bi.pop_front().unwrap();
        lazy.append(*x * y);
        let xu: u16 = (*x).try_into().unwrap();
        let yu: u16 = y.try_into().unwrap();
        reduced.append(mul_mod(xu, yu));
    }
    let got = intt(lazy.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg);
    let expect = oracle_intt(reduced.span());
    assert_felts_eq_u16(got.span(), expect);
}
