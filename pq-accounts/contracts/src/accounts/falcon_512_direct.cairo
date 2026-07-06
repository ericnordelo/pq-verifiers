//! Falcon-512 direct account contract.
//!
//! This account stores the same packed Falcon public key as the hint account, but validates
//! the compact direct signature layout: packed `s1` followed by the two salt felts.

#[starknet::contract(account)]
pub mod Falcon512DirectAccount {
    use pqbench_falcon_512::Falcon512DirectVerifier;
    use starknet::account::Call;
    use starknet::storage::{MutableVecTrait, StoragePointerReadAccess, Vec, VecTrait};
    use crate::utils::execution;
    use crate::utils::interface::{IFeltArrayDeployable, IFeltArrayPublicKey, IPqAccount};

    #[storage]
    struct Storage {
        public_key: Vec<felt252>,
    }

    /// Initializes the account with the packed Falcon public key used for validation.
    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        for felt in public_key {
            self.public_key.push(felt);
        }
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
    impl DeployableImpl of IFeltArrayDeployable<ContractState> {
        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: Array<felt252>,
        ) -> felt252 {
            let _ = class_hash;
            let _ = contract_address_salt;
            let _ = public_key;
            self.validate_transaction()
        }
    }

    #[abi(embed_v0)]
    impl PublicKeyImpl of IFeltArrayPublicKey<ContractState> {
        fn get_public_key(self: @ContractState) -> Array<felt252> {
            self.read_public_key()
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

        /// Reads the stored public key into the verifier's packed felt layout.
        fn read_public_key(self: @ContractState) -> Array<felt252> {
            let mut public_key = array![];
            let len = self.public_key.len();
            let mut i = 0;
            while i != len {
                public_key.append(self.public_key.at(i).read());
                i += 1;
            }
            public_key
        }

        /// Verifies a signature span against the stored public key.
        fn is_valid_signature_span(
            self: @ContractState, hash: felt252, signature: Span<felt252>,
        ) -> bool {
            Falcon512DirectVerifier::verify(hash, self.read_public_key().span(), signature)
        }
    }
}
