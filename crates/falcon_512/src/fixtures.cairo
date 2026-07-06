//! Generated Falcon-512 benchmark fixtures — a genuine keypair and signature per
//! hash-to-point backend (`blake` for the BLAKE2s variants, `shake` for the standard
//! SHAKE-256 variant, `poseidon` for the native-Poseidon variant). Each exposes `msg()`,
//! `public_key()`, and `signature()`. Regenerate with `scripts/gen_falcon_fixture.py`
//! (`--variant shake` / `--variant poseidon` for the others).

pub mod blake;
pub mod poseidon;
pub mod shake;
