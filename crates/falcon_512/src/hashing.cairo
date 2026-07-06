//! Message-hashing layer for Falcon-512: the hash-to-point (two interchangeable XOF
//! backends, BLAKE2s and standard SHAKE-256) and the SHAKE-256 extendable-output function
//! that the standard backend is built on.

pub mod hash_to_point;
pub mod shake256;
