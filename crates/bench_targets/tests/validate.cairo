//! In-`__validate__` benchmark scenario (paired-test subtraction).
//!
//! `bench_validate_<scheme>` deploys the account mock and calls `validate()`;
//! `bench_validate_base_<scheme>` deploys it and sets up the same cheats but does NOT call.
//! validate_cost = bench_validate_<scheme> - bench_validate_base_<scheme>, which cancels the
//! deploy cost and isolates the realistic validation call (tx-info read + storage read +
//! deserialization + verify + dispatch).

use openzeppelin_testing::constants::stark::KEY_PAIR;
use openzeppelin_testing::declare_and_deploy;
use openzeppelin_testing::signing::SerializedSigning;
use pqbench_falcon_512::{bench_fixture, bench_fixture_shake};
use pqbench_targets::{IValidateBenchDispatcher, IValidateBenchDispatcherTrait};
use snforge_std::{start_cheat_signature_global, start_cheat_transaction_hash_global};

const MSG: felt252 = 'BENCH_MSG';

/// Falcon accounts take the 29-felt public key as an `Array<felt252>` constructor arg,
/// so the deploy calldata is its Serde encoding (length-prefixed).
fn falcon_calldata() -> Array<felt252> {
    let mut calldata = array![];
    bench_fixture::public_key().serialize(ref calldata);
    calldata
}

/// The SHAKE fixture has its own keypair, so its deploy calldata is that key's encoding.
fn falcon_shake_calldata() -> Array<felt252> {
    let mut calldata = array![];
    bench_fixture_shake::public_key().serialize(ref calldata);
    calldata
}

/// The direct variant's 31-felt signature is the `s1 ‖ salt` prefix of the hint signature.
fn signature_direct() -> Array<felt252> {
    let mut out = array![];
    let mut prefix = bench_fixture::signature().span().slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
}

#[test]
fn bench_validate_base_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let address = declare_and_deploy("EcdsaStarkAccount", array![key_pair.public_key]);
    start_cheat_transaction_hash_global(MSG);
    start_cheat_signature_global(signature.span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(signature.len() == 2);
}

#[test]
fn bench_validate_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let address = declare_and_deploy("EcdsaStarkAccount", array![key_pair.public_key]);
    start_cheat_transaction_hash_global(MSG);
    start_cheat_signature_global(signature.span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512() {
    let address = declare_and_deploy("Falcon512Account", falcon_calldata());
    start_cheat_transaction_hash_global(bench_fixture::msg());
    start_cheat_signature_global(bench_fixture::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(bench_fixture::signature().len() == 60);
}

#[test]
fn bench_validate_falcon_512() {
    let address = declare_and_deploy("Falcon512Account", falcon_calldata());
    start_cheat_transaction_hash_global(bench_fixture::msg());
    start_cheat_signature_global(bench_fixture::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512_direct() {
    let address = declare_and_deploy("Falcon512DirectAccount", falcon_calldata());
    start_cheat_transaction_hash_global(bench_fixture::msg());
    start_cheat_signature_global(signature_direct().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(signature_direct().len() == 31);
}

#[test]
fn bench_validate_falcon_512_direct() {
    let address = declare_and_deploy("Falcon512DirectAccount", falcon_calldata());
    start_cheat_transaction_hash_global(bench_fixture::msg());
    start_cheat_signature_global(signature_direct().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}

#[test]
fn bench_validate_base_falcon_512_shake() {
    let address = declare_and_deploy("Falcon512ShakeAccount", falcon_shake_calldata());
    start_cheat_transaction_hash_global(bench_fixture_shake::msg());
    start_cheat_signature_global(bench_fixture_shake::signature().span());
    let _dispatcher = IValidateBenchDispatcher { contract_address: address };
    assert!(bench_fixture_shake::signature().len() == 60);
}

#[test]
fn bench_validate_falcon_512_shake() {
    let address = declare_and_deploy("Falcon512ShakeAccount", falcon_shake_calldata());
    start_cheat_transaction_hash_global(bench_fixture_shake::msg());
    start_cheat_signature_global(bench_fixture_shake::signature().span());
    let dispatcher = IValidateBenchDispatcher { contract_address: address };
    let result = dispatcher.validate();
    assert!(result == starknet::VALIDATED);
}
