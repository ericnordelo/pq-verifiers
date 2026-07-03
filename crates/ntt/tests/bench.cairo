//! Benchmark scenarios for the NTT engine (paired-test subtraction, as everywhere in
//! this repo): `bench_ntt_base_512` builds the inputs and config but does not
//! transform; the others add the measured work. These pairs feed the efficiency
//! ratchet (`efficiency_baseline.json` via `scripts/check_efficiency.py`).

use pqbench_ntt::engine::{intt, ntt};
use pqbench_ntt::falcon512::{REDUCED_BITS, config};

fn pseudorandom_felts(seed: u64, n: u32) -> Array<felt252> {
    let mut f: Array<felt252> = array![];
    let mut state: u64 = seed;
    for _ in 0..n {
        state = (state * 1664525 + 1013904223) % 0x100000000;
        f.append((state % 12289).into());
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

/// Forward + inverse (the roundtrip); INTT cost = roundtrip - fwd.
#[test]
fn bench_ntt_roundtrip_512() {
    let f = pseudorandom_felts(1, 512);
    let cfg = config();
    let out = ntt(f.span(), @cfg);
    let back = intt(out.span(), REDUCED_BITS, 12289, @cfg);
    assert!(back.len() == 512);
}
