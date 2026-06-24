//! STUB — placeholder for a Falcon-512 (FN-DSA) verifier. NOT a real implementation.
//!
//! It exists to validate the plug-in shape and the report's handling of pending schemes.
//! A real implementation will parse a 29-felt packed NTT-domain public key and a Falcon
//! signature, run the NTT (or check a signer-supplied multiplication hint) and the integer
//! norm bound. See `PORTING.md` in this crate for the concrete port plan (from s2morrow,
//! MIT) and docs/starknet-pq-account-research.md (sections 4-5) for the design rationale.

use pqbench_interface::PqSignatureVerifier;

/// Encoding (planned): `public_key` = 29 felts (512 NTT coeffs packed base-Q),
/// `signature` = ~22 felts (s1 + salt).
pub impl Falcon512Verifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        // Placeholder: shape check only. Real verification not implemented.
        let _ = message_hash;
        public_key.len() == 29 && signature.len() == 22
    }
}
