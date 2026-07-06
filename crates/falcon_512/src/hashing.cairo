//! Message-hashing layer for Falcon-512: the hash-to-point (three interchangeable
//! backends — BLAKE2s, standard SHAKE-256, and native Poseidon) and the SHAKE-256
//! extendable-output function that the standard backend is built on.

pub mod hash_to_point;
pub mod shake256;
