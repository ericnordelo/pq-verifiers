//! Benchmark scenarios for the ML-DSA-44 verifier (STUB).
//! Numbers are NOT meaningful until the verifier is implemented.

use pqbench_interface::PqSignatureVerifier;
use pqbench_ml_dsa_44::MlDsa44Verifier;

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
fn bench_baseline_ml_dsa_44() {
    let public_key = dummy(43);
    let signature = dummy(79);
    assert!(public_key.len() == 43 && signature.len() == 79);
}

#[test]
fn bench_verify_ml_dsa_44() {
    let public_key = dummy(43);
    let signature = dummy(79);
    let valid = MlDsa44Verifier::verify(MSG, public_key.span(), signature.span());
    assert!(valid);
}
