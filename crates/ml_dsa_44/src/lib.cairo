//! STUB — placeholder for an ML-DSA-44 (CRYSTALS-Dilithium, FIPS 204) verifier.
//! NOT a real implementation.
//!
//! A real implementation's cost is expected to be SHAKE-dominated in Cairo: NTT over
//! q=8380417 plus heavy SHAKE-256 hashing (built on the keccak builtin). See
//! docs/starknet-pq-account-research.md (sections 3-4).

use pqbench_interface::PqSignatureVerifier;

/// Encoding (planned, packed ~31 bytes/felt): `public_key` ~43 felts (1312 B),
/// `signature` ~79 felts (2420 B).
pub impl MlDsa44Verifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        let _ = message_hash;
        public_key.len() == 43 && signature.len() == 79
    }
}
