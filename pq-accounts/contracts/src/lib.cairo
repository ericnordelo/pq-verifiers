//! Starknet account contracts backed by the signature verifiers in this repository.
//!
//! These contracts expose the protocol account entrypoints used by Starknet for invoke,
//! declare, and deploy-account transactions. Each concrete account stores the public-key
//! encoding required by its verifier and validates `tx_info.signature` against
//! `tx_info.transaction_hash`.
//!
//! Layout: `accounts` holds the deployable account contracts (one module per verifier
//! scheme); `utils` holds the shared account interfaces and the execution/validation flow.

pub mod accounts;
pub mod utils;
