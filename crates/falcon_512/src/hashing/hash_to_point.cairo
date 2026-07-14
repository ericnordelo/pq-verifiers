//! Hash-to-point for Falcon-512, three backends sharing one rejection rule
//! ([`push_candidate`]): the non-standard BLAKE2s counter-mode construction
//! ([`hash_to_point_512`]), the standard SHAKE-256 construction of the Falcon spec
//! ([`hash_to_point_shake_512`], interoperable with stock signers like falcon.py), and a
//! Poseidon squeeze over the native `hades_permutation` builtin
//! ([`hash_to_point_poseidon_512`], non-standard but native and inexpensive).
//!
//! ## BLAKE2s backend
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
//!
//! The XOF is BLAKE2s in counter mode (the Cairo-native `core::blake` builtin), not the
//! SHAKE-256 of FIPS 206: signatures are NOT FIPS-206-interoperable, and the off-chain
//! signer must hash with this exact construction (see `scripts/gen_falcon_fixture.py`).

use core::blake::{blake2s_compress, blake2s_finalize};
use core::poseidon::hades_permutation;
use corelib_imports::bounded_int::{
    BoundedInt, DivRemHelper, UnitInt, bounded_int_div_rem, downcast, upcast,
};
use super::shake256::keccak_f1600;

/// blake2s-256 initial state: the BLAKE2s IV with the standard parameter word
/// (digest_length = 32, key = 0, fanout = 1, depth = 1) XORed into h[0].
const BLAKE2S_256_INIT: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Rejection bound: the largest multiple of Q below 2^16 (5 * 12289).
const REJECT_BOUND: u32 = 61445;

/// Each salt felt must fit in 20 bytes.
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000_u256;

/// Total bytes hashed per counter block: 40 (salt) + 32 (message hash) + 4 (counter).
const HASH_INPUT_BYTES: u32 = 76;

// Exact bounds for reading a felt's low 240 bits as little-endian 16-bit words.
// Each division peels one word; the final quotient after seven divisions is itself
// one 16-bit word for the low half and is discarded for the high half.
type Word16 = BoundedInt<0, 65535>;
type AcceptedWord = BoundedInt<0, 61444>;
type Base16 = UnitInt<65536>;
type Quot112 = BoundedInt<0, 5192296858534827628530496329220095>;
type Quot96 = BoundedInt<0, 79228162514264337593543950335>;
type Quot80 = BoundedInt<0, 1208925819614629174706175>;
type Quot64 = BoundedInt<0, 18446744073709551615>;
type Quot48 = BoundedInt<0, 281474976710655>;
type Quot32 = BoundedInt<0, 4294967295>;
type PoseidonQ = UnitInt<12289>;
type PoseidonZq = BoundedInt<0, 12288>;

const BASE16_NZ: NonZero<Base16> = 65536;
const POSEIDON_Q_NZ: NonZero<PoseidonQ> = 12289;

impl DivRemU128ByBase16 of DivRemHelper<u128, Base16> {
    type DivT = Quot112;
    type RemT = Word16;
}

impl DivRemQuot112ByBase16 of DivRemHelper<Quot112, Base16> {
    type DivT = Quot96;
    type RemT = Word16;
}

impl DivRemQuot96ByBase16 of DivRemHelper<Quot96, Base16> {
    type DivT = Quot80;
    type RemT = Word16;
}

impl DivRemQuot80ByBase16 of DivRemHelper<Quot80, Base16> {
    type DivT = Quot64;
    type RemT = Word16;
}

impl DivRemQuot64ByBase16 of DivRemHelper<Quot64, Base16> {
    type DivT = Quot48;
    type RemT = Word16;
}

impl DivRemQuot48ByBase16 of DivRemHelper<Quot48, Base16> {
    type DivT = Quot32;
    type RemT = Word16;
}

impl DivRemQuot32ByBase16 of DivRemHelper<Quot32, Base16> {
    type DivT = Word16;
    type RemT = Word16;
}

impl DivRemAcceptedWordByPoseidonQ of DivRemHelper<AcceptedWord, PoseidonQ> {
    type DivT = BoundedInt<0, 4>;
    type RemT = PoseidonZq;
}

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

/// ## SHAKE-256 backend
///
/// The standard Falcon (FIPS 206) construction: absorb `salt || message_hash` with
/// SHAKE-256, then consume the squeezed stream as big-endian 16-bit words, applying the
/// shared [`push_candidate`] rule (accept `word % Q` while `word < 5Q`) until 512
/// coefficients are collected. Unlike the BLAKE2s backend this is interoperable with any
/// standards-compliant Falcon signer (e.g. falcon.py). The message hash is absorbed as
/// its 32 little-endian bytes, the salt as its two 20-byte little-endian halves.
///
/// The sponge is driven directly on the Keccak lanes: the 72-byte input fits a single
/// rate block whose padded lanes are assembled straight from the salt and message-hash
/// limbs, and squeezing reads candidate words from the 17 rate lanes in place
/// ([`push_lane_words`]), permuting again only while more candidates are needed.

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)` with the standard
/// SHAKE-256 construction. Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_shake_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let mh: u256 = message_hash.into();

    // The absorbed block, assembled directly as little-endian lanes: bytes 0..40 hold
    // the salt, 40..72 the message hash, byte 72 the 0x1F SHAKE domain byte, and byte
    // 135 the pad10*1 terminator. The sponge state starts at zero, so this first
    // (and only) absorbed block IS the pre-permutation state.
    let two64: NonZero<u128> = 0x10000000000000000_u128.try_into().unwrap();
    let two32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (a1, a0) = DivRem::div_rem(sa.low, two64); // salt_a bytes 0..8 and 8..16
    let (sbq, sb0) = DivRem::div_rem(sb.low, two32); // salt_b bytes 0..4 and 4..16
    let (sb12, l3) = DivRem::div_rem(sbq, two64); // salt_b bytes 4..12 -> lane 3
    let (m1, m0) = DivRem::div_rem(mh.low, two64);
    let (m3, m2) = DivRem::div_rem(mh.high, two64);
    // Lane 2: salt_a bytes 16..20 in the low half, salt_b bytes 0..4 in the high half.
    let l2: u128 = (sa.high.into() + sb0.into() * 0x100000000).try_into().unwrap();
    // Lane 4: salt_b bytes 12..16 in the low half, salt_b bytes 16..20 in the high half.
    let l4: u128 = (sb12.into() + sb.high.into() * 0x100000000).try_into().unwrap();

    let mut state = keccak_f1600(
        [
            a0, a1, l2, l3, l4, m0, m1, m2, m3, 0x1f, 0, 0, 0, 0, 0, 0, 0x8000000000000000, 0, 0, 0,
            0, 0, 0, 0, 0,
        ],
    );

    let q32: NonZero<u32> = 12289_u32.try_into().unwrap();
    let two16: NonZero<u64> = 0x10000_u64.try_into().unwrap();
    let b256: NonZero<u64> = 0x100_u64.try_into().unwrap();
    let mut coeffs: Array<u16> = array![];
    loop {
        let mut lanes = state.span().slice(0, 17);
        while let Some(lane) = lanes.pop_front() {
            push_lane_words(*lane, two16, b256, q32, ref coeffs);
        }
        if coeffs.len() == 512 {
            break;
        }
        state = keccak_f1600(state);
    }
    Some(coeffs)
}

/// Read one squeezed rate lane (< 2^64) as four big-endian 16-bit candidate words. The
/// lane's bytes are little-endian, so each 16-bit chunk holds its stream word
/// byte-swapped: chunk = b0 + 256*b1 for the stream word 256*b0 + b1.
#[inline(always)]
fn push_lane_words(
    lane: u128, two16: NonZero<u64>, b256: NonZero<u64>, q32: NonZero<u32>, ref coeffs: Array<u16>,
) {
    let lane64: u64 = lane.try_into().unwrap();
    let (rest, c0) = DivRem::div_rem(lane64, two16);
    let (rest, c1) = DivRem::div_rem(rest, two16);
    let (c3, c2) = DivRem::div_rem(rest, two16);
    let (b1, b0) = DivRem::div_rem(c0, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
    let (b1, b0) = DivRem::div_rem(c1, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
    let (b1, b0) = DivRem::div_rem(c2, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
    let (b1, b0) = DivRem::div_rem(c3, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
}

/// ## Poseidon backend
///
/// Absorb `(salt_a, salt_b, message_hash)` as three field elements with the native Poseidon
/// permutation (`hades_permutation`, a Starknet builtin), then squeeze — take the two rate
/// elements `(s0, s1)` of the state, read 15 little-endian 16-bit words from the low 240
/// bits of each (uniform, since the field prime exceeds `2^251`), apply the shared
/// [`push_candidate`] rule, and permute the state again for the next block until 512
/// coefficients are collected.
///
/// Non-standard (Poseidon is not in the Falcon spec), so the off-chain signer must match
/// this construction (see `scripts/gen_falcon_fixture.py --variant poseidon`). Every step
/// is a native field operation, so the hash-to-point is inexpensive: on-chain verify cost
/// is close to the BLAKE2s backend and far below the pure-Cairo SHAKE-256 (the shared
/// NTT/hint core dominates either way).

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)` with a Poseidon squeeze.
/// Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_poseidon_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    // Absorb the three inputs, then squeeze the rate elements two felts at a time.
    let (mut s0, mut s1, mut s2) = hades_permutation(salt_a, salt_b, message_hash);
    let mut coeffs: Array<u16> = array![];
    while coeffs.len() != 512 {
        push_felt_words(s0, ref coeffs);
        push_felt_words(s1, ref coeffs);
        if coeffs.len() == 512 {
            break;
        }
        let (n0, n1, n2) = hades_permutation(s0, s1, s2);
        s0 = n0;
        s1 = n1;
        s2 = n2;
    }
    Some(coeffs)
}

/// Read the low 240 bits of `felt` as 15 little-endian 16-bit candidate words — 8 from
/// the low 128-bit half and 7 from the high half.
fn push_felt_words(felt: felt252, ref coeffs: Array<u16>) {
    let v: u256 = felt.into();
    push_u128_words8(v.low, ref coeffs);
    push_u128_words7(v.high, ref coeffs);
}

/// Feed all eight 16-bit words of a u128, low first, as rejection-sampled candidates.
#[inline(always)]
fn push_u128_words8(value: u128, ref coeffs: Array<u16>) {
    let (q1, w0) = bounded_int_div_rem(value, BASE16_NZ);
    let (q2, w1) = bounded_int_div_rem(q1, BASE16_NZ);
    let (q3, w2) = bounded_int_div_rem(q2, BASE16_NZ);
    let (q4, w3) = bounded_int_div_rem(q3, BASE16_NZ);
    let (q5, w4) = bounded_int_div_rem(q4, BASE16_NZ);
    let (q6, w5) = bounded_int_div_rem(q5, BASE16_NZ);
    let (w7, w6) = bounded_int_div_rem(q6, BASE16_NZ);
    push_poseidon_candidate(w0, ref coeffs);
    push_poseidon_candidate(w1, ref coeffs);
    push_poseidon_candidate(w2, ref coeffs);
    push_poseidon_candidate(w3, ref coeffs);
    push_poseidon_candidate(w4, ref coeffs);
    push_poseidon_candidate(w5, ref coeffs);
    push_poseidon_candidate(w6, ref coeffs);
    push_poseidon_candidate(w7, ref coeffs);
}

/// Feed the low seven 16-bit words of a u128 and discard its remaining high 16 bits.
#[inline(always)]
fn push_u128_words7(value: u128, ref coeffs: Array<u16>) {
    let (q1, w0) = bounded_int_div_rem(value, BASE16_NZ);
    let (q2, w1) = bounded_int_div_rem(q1, BASE16_NZ);
    let (q3, w2) = bounded_int_div_rem(q2, BASE16_NZ);
    let (q4, w3) = bounded_int_div_rem(q3, BASE16_NZ);
    let (q5, w4) = bounded_int_div_rem(q4, BASE16_NZ);
    let (q6, w5) = bounded_int_div_rem(q5, BASE16_NZ);
    let (_, w6) = bounded_int_div_rem(q6, BASE16_NZ);
    push_poseidon_candidate(w0, ref coeffs);
    push_poseidon_candidate(w1, ref coeffs);
    push_poseidon_candidate(w2, ref coeffs);
    push_poseidon_candidate(w3, ref coeffs);
    push_poseidon_candidate(w4, ref coeffs);
    push_poseidon_candidate(w5, ref coeffs);
    push_poseidon_candidate(w6, ref coeffs);
}

/// Apply the unchanged Falcon rejection rule to one exact 16-bit Poseidon word.
#[inline(always)]
fn push_poseidon_candidate(candidate: Word16, ref coeffs: Array<u16>) {
    if coeffs.len() == 512 {
        return;
    }
    match downcast::<Word16, AcceptedWord>(candidate) {
        Some(accepted) => {
            let (_, r) = bounded_int_div_rem(accepted, POSEIDON_Q_NZ);
            coeffs.append(upcast(r));
        },
        None => {},
    }
}

/// Little-endian u32 limbs of a u128.
fn limbs_128(x: u128) -> (u32, u32, u32, u32) {
    let two_pow_32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (rest, l0) = DivRem::div_rem(x, two_pow_32);
    let (rest, l1) = DivRem::div_rem(rest, two_pow_32);
    let (l3, l2) = DivRem::div_rem(rest, two_pow_32);
    (l0.try_into().unwrap(), l1.try_into().unwrap(), l2.try_into().unwrap(), l3.try_into().unwrap())
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
