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
use pqbench_targets::{IValidateBenchDispatcher, IValidateBenchDispatcherTrait};
use snforge_std::{start_cheat_signature_global, start_cheat_transaction_hash_global};

const MSG: felt252 = 'BENCH_MSG';

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
