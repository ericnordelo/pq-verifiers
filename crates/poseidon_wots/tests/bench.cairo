//! Benchmark scenarios for the Poseidon-WOTS+ verifier (STUB).
//! Numbers are NOT meaningful until the verifier is implemented.

use pqbench_interface::PqSignatureVerifier;
use pqbench_poseidon_wots::PoseidonWotsVerifier;

const MSG: felt252 = 'BENCH_MSG';

fn dummy(n: u32) -> Array<felt252> {
    let mut a = array![];
    let mut i: u32 = 0;
    while i < n {
        a.append(i.into());
        i += 1;
    }
    a
}

#[test]
fn bench_baseline_poseidon_wots() {
    let public_key = dummy(1);
    let signature = dummy(560);
    assert!(public_key.len() == 1 && signature.len() == 560);
}

#[test]
fn bench_verify_poseidon_wots() {
    let public_key = dummy(1);
    let signature = dummy(560);
    let valid = PoseidonWotsVerifier::verify(MSG, public_key.span(), signature.span());
    assert!(valid);
}
