//! Reusable account component for verifiers behind the `PqSignatureVerifier` interface.
//!
//! [`PqAccountComponent`] carries the complete account flow shared by every array-key
//! account in this package: packed public-key storage, the SNIP-6 entrypoints
//! (`__execute__`, `__validate__`, `__validate_declare__`, `is_valid_signature`,
//! `supports_interface`), deploy-account validation, and the public-key reader. It is
//! generic over the verifier implementation, so a concrete account contract is just an
//! embedding of this component with the scheme it authenticates with — see the modules
//! under `accounts/` for the per-scheme instantiations.

#[starknet::component]
pub mod PqAccountComponent {
    use pqbench_interface::PqSignatureVerifier;
    use starknet::account::Call;
    use starknet::storage::{MutableVecTrait, StoragePointerReadAccess, Vec, VecTrait};
    use crate::utils::execution;
    use crate::utils::interface::{IFeltArrayDeployable, IFeltArrayPublicKey, IPqAccount};

    #[storage]
    pub struct Storage {
        pub public_key: Vec<felt252>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {}

    #[embeddable_as(AccountImpl)]
    impl Account<
        TContractState,
        impl Verifier: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IPqAccount<ComponentState<TContractState>> {
        fn __execute__(self: @ComponentState<TContractState>, calls: Array<Call>) {
            execution::assert_protocol_caller();
            execution::assert_valid_tx_version();
            execution::execute_calls(calls.span());
        }

        fn __validate__(self: @ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            let _ = calls;
            self.validate_transaction::<Verifier>()
        }

        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252,
        ) -> felt252 {
            let _ = class_hash;
            self.validate_transaction::<Verifier>()
        }

        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            execution::signature_result(
                Verifier::verify(hash, self.read_public_key().span(), signature.span()),
            )
        }

        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252,
        ) -> bool {
            execution::supports_account_interface(interface_id)
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        impl Verifier: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IFeltArrayDeployable<ComponentState<TContractState>> {
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: Array<felt252>,
        ) -> felt252 {
            let _ = class_hash;
            let _ = contract_address_salt;
            let _ = public_key;
            self.validate_transaction::<Verifier>()
        }
    }

    #[embeddable_as(PublicKeyImpl)]
    impl PublicKey<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of IFeltArrayPublicKey<ComponentState<TContractState>> {
        fn get_public_key(self: @ComponentState<TContractState>) -> Array<felt252> {
            self.read_public_key()
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Stores the packed public key the embedded verifier validates against.
        fn initializer(ref self: ComponentState<TContractState>, public_key: Array<felt252>) {
            for felt in public_key {
                self.public_key.push(felt);
            }
        }

        /// Validates the current transaction hash against the transaction signature.
        fn validate_transaction<impl Verifier: PqSignatureVerifier>(
            self: @ComponentState<TContractState>,
        ) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            execution::assert_valid_signature(
                Verifier::verify(
                    tx_info.transaction_hash, self.read_public_key().span(), tx_info.signature,
                ),
            )
        }

        /// Reads the stored public key into the verifier's packed felt layout.
        fn read_public_key(self: @ComponentState<TContractState>) -> Array<felt252> {
            let mut public_key = array![];
            let len = self.public_key.len();
            let mut i = 0;
            while i != len {
                public_key.append(self.public_key.at(i).read());
                i += 1;
            }
            public_key
        }
    }
}
