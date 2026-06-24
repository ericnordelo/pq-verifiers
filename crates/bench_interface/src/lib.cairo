//! Common interface and shared constants for the post-quantum signature-verifier
//! benchmark harness.
//!
//! Every candidate verifier (ECDSA baseline, Falcon, ML-DSA, hash-based, ...) implements
//! [`PqSignatureVerifier`], so the benchmark rig can swap them behind one uniform surface
//! and measure each identically. This is intentionally the same shape as the OZ account
//! plug point `_is_valid_signature(hash, signature)`, so a winning verifier drops straight
//! into an `AccountComponent` later.

/// Uniform verification surface for a signature scheme.
///
/// `public_key` and `signature` are felt-encoded with a scheme-specific layout
/// (e.g. Falcon-512 packs 512 NTT-domain coefficients into 29 `felt252` slots).
/// Implementations MUST be self-contained: no external contract calls, since
/// Starknet forbids them during `__validate__`.
pub trait PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool;
}

/// Max Cairo steps a transaction's validation may consume.
/// Source: blockifier `validate_max_n_steps` (versioned-constants, v0.13.4+).
pub const VALIDATE_MAX_STEPS: u64 = 1_000_000;

/// Max L2 (Sierra) gas a transaction's validation may consume.
/// Source: blockifier `validate_max_sierra_gas` (versioned-constants, v0.13.4+).
pub const VALIDATE_MAX_L2_GAS: u64 = 100_000_000;

/// L2 gas charged per felt of calldata/signature payload.
/// Derived: 0.128 L1 gas/felt × 40_000 L2 gas/L1 gas.
pub const L2_GAS_PER_CALLDATA_FELT: u64 = 5_120;
