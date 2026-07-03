// SPDX-License-Identifier: MIT
//
// Original to this crate (not ported from s2morrow, whose hash-to-point is Poseidon-based):
// Falcon's spec hash-to-point (rejection sampling of 16-bit candidates, FIPS 206 / falcon.py
// `Falcon.__hash_to_point__`) with the XOF instantiated as BLAKE2s in counter mode instead
// of SHAKE-256, to use the Cairo-native `core::blake` builtin. NON-STANDARD: signatures are
// not FIPS-206-interoperable; the off-chain signer must hash with the same construction
// (see scripts/gen_falcon_fixture.py).

//! BLAKE2s-based hash-to-point for Falcon-512.
//!
//! Maps `(message_hash, salt)` to 512 coefficients in `[0, Q)`:
//!
//! ```text
//! prefix   = salt_a[20 bytes LE] || salt_b[20 bytes LE] || message_hash[32 bytes LE]
//! digest_i = blake2s-256(prefix || u32_le(i))          for i = 0, 1, 2, ...
//! ```
//!
//! Each digest yields 16 little-endian u16 candidates, consumed in order; candidates
//! < 61445 (= 5Q, the largest multiple of Q below 2^16) are accepted as `candidate % Q`
//! (uniform in `[0, Q)`), until 512 coefficients are collected — the same rejection rule
//! as the SHAKE-256 construction in the Falcon spec.
//!
//! The salt is 40 bytes (the FIPS-206 salt length), carried as two felts of 20 bytes each.

use core::blake::{blake2s_compress, blake2s_finalize};

/// blake2s-256 initial state: the BLAKE2s IV with the standard parameter word
/// (digest_length = 32, key = 0, fanout = 1, depth = 1) XORed into h[0].
const BLAKE2S_256_INIT: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
    0x5BE0CD19,
];

/// Rejection bound: the largest multiple of Q below 2^16 (5 * 12289).
const REJECT_BOUND: u32 = 61445;

/// Each salt felt must fit in 20 bytes.
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000_u256;

/// Total bytes hashed per counter block: 40 (salt) + 32 (message hash) + 4 (counter).
const HASH_INPUT_BYTES: u32 = 76;

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)`.
/// Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let (a0, a1, a2, a3, a4) = limbs_160(sa);
    let (b0, b1, b2, b3, b4) = limbs_160(sb);
    let mh: u256 = message_hash.into();
    let (m0, m1, m2, m3) = limbs_128(mh.low);
    let (m4, m5, m6, m7) = limbs_128(mh.high);

    // Bytes 0..63 (identical for every counter, so compressed once): the 40-byte salt
    // followed by the first 24 bytes of the message hash.
    let prefix_state = blake2s_compress(
        BoxTrait::new(BLAKE2S_256_INIT),
        64,
        BoxTrait::new([a0, a1, a2, a3, a4, b0, b1, b2, b3, b4, m0, m1, m2, m3, m4, m5]),
    )
        .unbox();

    let sixteen_bits: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    let q32: NonZero<u32> = 12289_u32.try_into().unwrap();
    let mut coeffs: Array<u16> = array![];
    let mut ctr: u32 = 0;
    while coeffs.len() != 512 {
        // Bytes 64..75: the last 8 bytes of the message hash and the LE counter.
        let digest = blake2s_finalize(
            BoxTrait::new(prefix_state),
            HASH_INPUT_BYTES,
            BoxTrait::new([m6, m7, ctr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        )
            .unbox();
        let mut words = digest.span();
        while let Some(w) = words.pop_front() {
            // Two LE u16 candidates per digest word, low half first.
            let (hi, lo) = DivRem::div_rem(*w, sixteen_bits);
            push_candidate(lo, q32, ref coeffs);
            push_candidate(hi, q32, ref coeffs);
        }
        ctr += 1;
    }
    Some(coeffs)
}

/// Rejection-sample one 16-bit candidate: accept `candidate % Q` while below the
/// bound and 512 coefficients have not been collected yet.
#[inline(always)]
fn push_candidate(candidate: u32, q32: NonZero<u32>, ref coeffs: Array<u16>) {
    if coeffs.len() != 512 && candidate < REJECT_BOUND {
        let (_, r) = DivRem::div_rem(candidate, q32);
        coeffs.append(r.try_into().unwrap());
    }
}

/// Little-endian u32 limbs of a u128.
fn limbs_128(x: u128) -> (u32, u32, u32, u32) {
    let two_pow_32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (rest, l0) = DivRem::div_rem(x, two_pow_32);
    let (rest, l1) = DivRem::div_rem(rest, two_pow_32);
    let (l3, l2) = DivRem::div_rem(rest, two_pow_32);
    (
        l0.try_into().unwrap(), l1.try_into().unwrap(), l2.try_into().unwrap(),
        l3.try_into().unwrap(),
    )
}

/// Little-endian u32 limbs of a 160-bit value (caller checks the range).
fn limbs_160(x: u256) -> (u32, u32, u32, u32, u32) {
    let (l0, l1, l2, l3) = limbs_128(x.low);
    (l0, l1, l2, l3, x.high.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::{TWO_POW_160, hash_to_point_512};

    const MSG: felt252 = 'BENCH_MSG';

    // Known-answer vectors generated with the reference Python construction
    // (hashlib.blake2s counter mode; see scripts/gen_falcon_fixture.py).
    #[test]
    fn test_hash_to_point_kat() {
        let coeffs = hash_to_point_512(MSG, 1, 2).unwrap();
        assert_eq!(coeffs.len(), 512);
        let first8: [u16; 8] = [9961, 3944, 2517, 2545, 1832, 3277, 10883, 3861];
        let last8: [u16; 8] = [5236, 2206, 424, 1825, 8022, 8816, 4999, 9640];
        let mid4: [u16; 4] = [9941, 5062, 7268, 7838];
        let mut i: u32 = 0;
        for expected in first8.span() {
            assert_eq!(*coeffs.at(i), *expected);
            i += 1;
        }
        let mut j: u32 = 504;
        for expected in last8.span() {
            assert_eq!(*coeffs.at(j), *expected);
            j += 1;
        }
        let mut k: u32 = 255;
        for expected in mid4.span() {
            assert_eq!(*coeffs.at(k), *expected);
            k += 1;
        }
    }

    #[test]
    fn test_hash_to_point_domain_separation() {
        // Different message, salt halves, or salt order all change the point.
        let base = hash_to_point_512(MSG, 1, 2).unwrap();
        let other_msg = hash_to_point_512('OTHER_MSG', 1, 2).unwrap();
        let other_salt = hash_to_point_512(MSG, 2, 1).unwrap();
        assert_ne!(base.span(), other_msg.span());
        assert_ne!(base.span(), other_salt.span());
    }

    #[test]
    fn test_hash_to_point_rejects_oversized_salt() {
        let too_big: felt252 = TWO_POW_160.try_into().unwrap();
        assert!(hash_to_point_512(MSG, too_big, 0).is_none());
        assert!(hash_to_point_512(MSG, 0, too_big).is_none());
        // 2^160 - 1 is the largest valid salt half.
        assert!(hash_to_point_512(MSG, too_big - 1, too_big - 1).is_some());
    }
}
