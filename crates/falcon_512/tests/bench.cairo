//! Benchmark scenarios for the Falcon-512 verifier (STUB).
//! Builds dummy inputs of the planned felt sizes so the harness produces a row and the
//! plug-in path is exercised. Numbers are NOT meaningful until the verifier is implemented.

use pqbench_falcon_512::Falcon512Verifier;
use pqbench_interface::PqSignatureVerifier;

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
fn bench_baseline_falcon_512() {
    let public_key = dummy(29);
    let signature = dummy(22);
    assert!(public_key.len() == 29 && signature.len() == 22);
}

#[test]
fn bench_verify_falcon_512() {
    let public_key = dummy(29);
    let signature = dummy(22);
    let valid = Falcon512Verifier::verify(MSG, public_key.span(), signature.span());
    assert!(valid);
}
