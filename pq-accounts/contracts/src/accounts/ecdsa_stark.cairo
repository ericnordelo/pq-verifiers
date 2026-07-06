//! ECDSA-STARK account contract.
//!
//! This account stores a single STARK-curve public key felt and validates transaction
//! signatures with `pqbench_ecdsa_stark`. It is the classical control account for the
//! package and mirrors the same signature layout as the verifier crate: `[r, s]`.

#[starknet::contract(account)]
pub mod EcdsaStarkAccount {
    use pqbench_ecdsa_stark::EcdsaStarkVerifier;
    use starknet::account::Call;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use crate::utils::execution;
    use crate::utils::interface::{IPqAccount, ISingleFeltDeployable, ISingleFeltPublicKey};

    #[storage]
    struct Storage {
        public_key: felt252,
    }

    /// Initializes the account with the STARK-curve public key used for validation.
    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.public_key.write(public_key);
    }

    #[abi(embed_v0)]
    impl AccountImpl of IPqAccount<ContractState> {
        fn __execute__(self: @ContractState, calls: Array<Call>) {
            execution::assert_protocol_caller();
            execution::assert_valid_tx_version();
            execution::execute_calls(calls.span());
        }

        fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
            let _ = calls;
            self.validate_transaction()
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            let _ = class_hash;
            self.validate_transaction()
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            execution::signature_result(self.is_valid_signature_span(hash, signature.span()))
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            execution::supports_account_interface(interface_id)
        }
    }

    #[abi(embed_v0)]
    impl DeployableImpl of ISingleFeltDeployable<ContractState> {
        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252,
        ) -> felt252 {
            let _ = class_hash;
            let _ = contract_address_salt;
            let _ = public_key;
            self.validate_transaction()
        }
    }

    #[abi(embed_v0)]
    impl PublicKeyImpl of ISingleFeltPublicKey<ContractState> {
        fn get_public_key(self: @ContractState) -> felt252 {
            self.public_key.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Validates the current transaction hash against the transaction signature.
        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            execution::assert_valid_signature(
                self.is_valid_signature_span(tx_info.transaction_hash, tx_info.signature),
            )
        }

        /// Verifies a signature span against the stored public key.
        fn is_valid_signature_span(
            self: @ContractState, hash: felt252, signature: Span<felt252>,
        ) -> bool {
            EcdsaStarkVerifier::verify(hash, array![self.public_key.read()].span(), signature)
        }
    }
}
