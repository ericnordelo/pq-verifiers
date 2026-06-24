//! Account-mock contracts for the in-`__validate__` benchmark scenario.
//!
//! Each contract stores a public key and exposes `validate()`, which does exactly what an
//! account's `__validate__` does: read the transaction hash + signature from the tx info,
//! read the stored public key, and run the verifier. Measuring a deploy+call of this (with
//! a deploy-only baseline subtracted) captures the realistic validation cost — calldata
//! deserialization, storage read, dispatch, and verification — not just the bare verify.
//! Building these contracts also yields the contract-class size.

/// Minimal account-validation surface exposed for benchmarking.
#[starknet::interface]
pub trait IValidateBench<TState> {
    fn validate(self: @TState) -> felt252;
}

#[starknet::contract]
pub mod EcdsaStarkAccount {
    use pqbench_ecdsa_stark::EcdsaStarkVerifier;
    use pqbench_interface::PqSignatureVerifier;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::IValidateBench;

    #[storage]
    struct Storage {
        public_key: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.public_key.write(public_key);
    }

    #[abi(embed_v0)]
    impl ValidateBenchImpl of IValidateBench<ContractState> {
        fn validate(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let valid = EcdsaStarkVerifier::verify(
                tx_info.transaction_hash,
                array![self.public_key.read()].span(),
                tx_info.signature,
            );
            assert!(valid, "invalid signature");
            starknet::VALIDATED
        }
    }
}
