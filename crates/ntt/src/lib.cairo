//! Modular Number-Theoretic Transform (NTT) for Starknet.
//!
//! A reusable, scheme-agnostic NTT engine optimized for the Cairo cost model: butterfly
//! arithmetic runs natively in `felt252` (one field multiplication and a few additions per
//! butterfly, no per-operation modular reduction), and reduction happens in at most two
//! u128 passes per transform — [`engine::ntt_lazy`] skips the forward transform's final
//! pass entirely and reports the exact output bound instead. See `engine` for the
//! algorithm and its safety argument, which is additionally proven executable by
//! `scripts/gen_ntt_tables.py`.
//!
//! Parameter sets plug in through [`engine::NttConfig`]: a modulus, root tables, and a
//! leaf permutation. [`falcon512`] provides the Falcon-512 set (q = 12289, n = 512,
//! tprest/falcon.py interop convention — the same transform s2morrow uses); other
//! lattice schemes (Falcon-1024, ML-DSA) can define their own config without touching
//! the engine. [`falcon512_fast::ntt_falcon512_fast_unchecked`] is the generated,
//! fixed-parameter forward path for callers that already hold canonical Falcon-512
//! coefficients. Its name makes the unchecked `[0, q)` input precondition explicit.

pub mod bitrev;
pub mod engine;
pub mod falcon512;
pub mod falcon512_fast;
pub mod roots;
pub mod roots_felt;
pub mod roots_scaled;

pub use engine::{NttConfig, intt, ntt, ntt_lazy, reduce_felt};
pub use falcon512_fast::{ntt_falcon512_fast_u16_unchecked, ntt_falcon512_fast_unchecked};
