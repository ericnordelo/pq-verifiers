//! Falcon-512 SHAKE-256 account contract.
//!
//! This account stores the packed 29-felt NTT-domain public key and validates the same
//! 60-felt hint signature layout as the hint account, deriving the message point with the
//! standard SHAKE-256 hash-to-point of the Falcon specification. Signatures are therefore
//! interoperable with any standards-compliant Falcon signer (e.g. falcon.py) — no custom
//! hash construction on the signing side.

#[starknet::contract(account)]
pub mod Falcon512ShakeAccount {
    use pqbench_falcon_512::Falcon512ShakeVerifier;
    use crate::utils::account::PqAccountComponent;

    component!(path: PqAccountComponent, storage: account, event: AccountEvent);

    #[abi(embed_v0)]
    impl AccountImpl =
        PqAccountComponent::AccountImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl DeployableImpl =
        PqAccountComponent::DeployableImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl PublicKeyImpl = PqAccountComponent::PublicKeyImpl<ContractState>;

    impl InternalImpl = PqAccountComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: PqAccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: PqAccountComponent::Event,
    }

    /// Initializes the account with the packed Falcon public key used for validation.
    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        self.account.initializer(public_key);
    }
}
