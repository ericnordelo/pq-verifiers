//! Falcon-512 direct account contract.
//!
//! This account stores the same packed Falcon public key as the hint account, but validates
//! the compact direct signature layout: packed `s1` followed by the two salt felts. The
//! message point is derived with the BLAKE2s hash-to-point, so the off-chain signer must
//! use the matching construction.

#[starknet::contract(account)]
pub mod Falcon512DirectAccount {
    use pqbench_falcon_512::Falcon512DirectVerifier;
    use crate::utils::account::PqAccountComponent;

    component!(path: PqAccountComponent, storage: account, event: AccountEvent);

    #[abi(embed_v0)]
    impl AccountImpl =
        PqAccountComponent::AccountImpl<ContractState, Falcon512DirectVerifier>;
    #[abi(embed_v0)]
    impl DeployableImpl =
        PqAccountComponent::DeployableImpl<ContractState, Falcon512DirectVerifier>;
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
