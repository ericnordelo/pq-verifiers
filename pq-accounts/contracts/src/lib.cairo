//! Starknet account contracts backed by the signature verifiers in this repository.
//!
//! These contracts expose the protocol account entrypoints used by Starknet for invoke,
//! declare, and deploy-account transactions. Each concrete account stores the public-key
//! encoding required by its verifier and validates `tx_info.signature` against
//! `tx_info.transaction_hash`.

pub mod ecdsa_stark;
pub mod execution;
pub mod falcon_512;
pub mod falcon_512_direct;
pub mod interface;
