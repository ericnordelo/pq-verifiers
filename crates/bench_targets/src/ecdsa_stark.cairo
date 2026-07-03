//! Benchmark account for the ECDSA-STARK verifier (the classical control).
//!
//! Stores the STARK-curve public key as a single felt and validates the transaction
//! signature with `pqbench_ecdsa_stark`.

#[starknet::contract]
pub mod EcdsaStarkAccount {
    use pqbench_ecdsa_stark::EcdsaStarkVerifier;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use crate::IValidateBench;

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
                tx_info.transaction_hash, array![self.public_key.read()].span(), tx_info.signature,
            );
            assert!(valid, "invalid signature");
            starknet::VALIDATED
        }
    }
}
