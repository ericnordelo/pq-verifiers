//! Falcon-512 SHAKE-256 direct account contract.
//!
//! Validates the compact 31-felt direct signature layout (packed `s1` followed by the two
//! salt felts) with the standard SHAKE-256 hash-to-point of the Falcon specification and the
//! hint-free direct core (`s1*h` recomputed on-chain). It carries no signer-supplied hint,
//! so it mirrors a bare FIPS Falcon signature most closely; signatures are interoperable
//! with any standards-compliant Falcon signer.

#[starknet::contract(account)]
pub mod Falcon512ShakeDirectAccount {
    use pqbench_falcon_512::Falcon512ShakeDirectVerifier;
    use crate::utils::account::PqAccountComponent;

    component!(path: PqAccountComponent, storage: account, event: AccountEvent);

    #[abi(embed_v0)]
    impl AccountImpl =
        PqAccountComponent::AccountImpl<ContractState, Falcon512ShakeDirectVerifier>;
    #[abi(embed_v0)]
    impl DeployableImpl =
        PqAccountComponent::DeployableImpl<ContractState, Falcon512ShakeDirectVerifier>;
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
