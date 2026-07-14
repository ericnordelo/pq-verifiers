//! Benchmark scenarios for the NTT engine (paired-test subtraction, as everywhere in
//! this repo): `bench_ntt_base_512` builds the inputs and config but does not
//! transform; the others add the measured work. These pairs feed the efficiency
//! ratchet (`efficiency_baseline.json` via `scripts/check_efficiency.py`).

use pqbench_ntt::engine::{intt, ntt, ntt_lazy};
use pqbench_ntt::falcon512::{REDUCED_BITS, config};
use pqbench_ntt::{ntt_falcon512_fast_u16_unchecked, ntt_falcon512_fast_unchecked};

fn pseudorandom_felts(seed: u64, n: u32) -> Array<felt252> {
    let mut f: Array<felt252> = array![];
    let mut state: u64 = seed;
    for _ in 0..n {
        state = (state * 1664525 + 1013904223) % 0x100000000;
        f.append((state % 12289).into());
    }
    f
}

fn pseudorandom_u16(seed: u64, n: u32) -> Array<u16> {
    let mut f: Array<u16> = array![];
    let mut state: u64 = seed;
    for _ in 0..n {
        state = (state * 1664525 + 1013904223) % 0x100000000;
        f.append((state % 12289).try_into().unwrap());
    }
    f
}

/// Builds inputs and config but does NOT transform — the subtraction baseline.
#[test]
fn bench_ntt_base_512() {
    let f = pseudorandom_felts(1, 512);
    let cfg = config();
    assert!(f.len() == cfg.n);
}

/// One forward 512-point transform.
#[test]
fn bench_ntt_fwd_512() {
    let f = pseudorandom_felts(1, 512);
    let cfg = config();
    let out = ntt(f.span(), @cfg);
    assert!(out.len() == 512);
}

/// One forward 512-point transform without the final reduction pass.
#[test]
fn bench_ntt_fwd_lazy_512() {
    let f = pseudorandom_felts(1, 512);
    let cfg = config();
    let (out, _, _) = ntt_lazy(f.span(), @cfg);
    assert!(out.len() == 512);
}

/// Builds the fixed-parameter fast-path input but does NOT transform it.
#[test]
fn bench_ntt_falcon512_fast_base_512() {
    let f = pseudorandom_felts(1, 512);
    assert!(f.len() == 512);
}

/// One fully unrolled, fixed-parameter Falcon-512 forward transform.
#[test]
fn bench_ntt_falcon512_fast_512() {
    let f = pseudorandom_felts(1, 512);
    let out = ntt_falcon512_fast_unchecked(f.span());
    assert!(out.len() == 512);
}

/// Builds the fixed-parameter canonical-u16 input but does NOT transform it.
#[test]
fn bench_ntt_falcon512_fast_u16_base_512() {
    let f = pseudorandom_u16(1, 512);
    assert!(f.len() == 512);
}

/// One fully unrolled Falcon-512 transform over canonical `u16` coefficients.
#[test]
fn bench_ntt_falcon512_fast_u16_512() {
    let f = pseudorandom_u16(1, 512);
    let out = ntt_falcon512_fast_u16_unchecked(f.span());
    assert!(out.len() == 512);
}

/// Forward + inverse (the roundtrip); INTT cost = roundtrip - fwd.
#[test]
fn bench_ntt_roundtrip_512() {
    let f = pseudorandom_felts(1, 512);
    let cfg = config();
    let out = ntt(f.span(), @cfg);
    let back = intt(out.span(), REDUCED_BITS, 12289, @cfg);
    assert!(back.len() == 512);
}
