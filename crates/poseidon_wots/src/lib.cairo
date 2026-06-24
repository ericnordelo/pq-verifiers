//! STUB — placeholder for a Poseidon-instantiated hash-based verifier (WOTS+ / Merkle).
//! NOT a real implementation.
//!
//! This is the "Cairo-native" option: verification is pure Poseidon hashing + Merkle paths
//! (cheap on Starknet), but the scheme is NON-standard and its security budget must be
//! re-derived (Groebner + Grover + 252-bit field). Large signatures dominate calldata.
//! See docs/starknet-pq-account-research.md (sections 4, 8 option C).

use pqbench_interface::PqSignatureVerifier;

/// Encoding (planned): `public_key` = 1 felt (Merkle/hypertree root),
/// `signature` ~560 felts (WOTS+ chains + auth path).
pub impl PoseidonWotsVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let _ = message_hash;
        public_key.len() == 1 && signature.len() == 560
    }
}
