//! Reference baseline verifier: ECDSA over the STARK curve.
//!
//! This is the classical (NON-post-quantum) scheme OZ accounts use today. It exists in the
//! harness as a known-cheap control: it proves the measurement + report pipeline end-to-end
//! and gives every PQ candidate a familiar cost to be compared against.

use core::ecdsa::check_ecdsa_signature;
use pqbench_interface::PqSignatureVerifier;

/// Encoding (uniform felt layout for the harness):
/// - `public_key`: `[pk]` (1 felt, the STARK-curve public key)
/// - `signature`:  `[r, s]` (2 felts)
pub impl EcdsaStarkVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        if public_key.len() != 1 || signature.len() != 2 {
            return false;
        }
        check_ecdsa_signature(message_hash, *public_key.at(0), *signature.at(0), *signature.at(1))
    }
}
