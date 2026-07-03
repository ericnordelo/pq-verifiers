// SPDX-FileCopyrightText: 2025 StarkWare Industries Ltd.
//
// SPDX-License-Identifier: MIT
//
// Ported from s2morrow `packages/falcon/src/hash_to_point.cairo`
// (feltroidprime/s2morrow@4eff9ab9f5a4, `PoseidonHashToPoint` — the construction deployed
// in the live s2morrow wallet). Reimplemented with plain u128 div-rem (upstream builds on
// corelib-private `BoundedInt` chains; remainders do not depend on the quotient's type
// bounds, so the output is identical) and with the salt range validation upstream lacks,
// for parity with this crate's BLAKE2s construction. Port pinned by the upstream
// Rust <-> Cairo cross-language KAT (`scripts/data/falcon_poseidon_h2p_kat.json`).

//! Poseidon-based hash-to-point for Falcon-512 (s2morrow's deployed construction).
//!
//! Maps `(message_hash, salt)` to 512 coefficients in `[0, Q)`:
//!
//! ```text
//! seed         = poseidon_hash_span([message_hash, salt_a, salt_b])
//! (s0, s1, s2) = (seed, 0, 0)
//! 21 rounds:   (s0, s1, s2) = hades_permutation(s0, s1, s2); extract 12 from s0, 12 from s1
//! final round: (s0, _, _)   = hades_permutation(s0, s1, s2); extract 8 from s0
//! ```
//!
//! Extraction takes base-Q digits (successive remainders mod Q = 12289, least-significant
//! first): 6 from a felt's low u128 then 6 from its high part (the final round takes
//! 6 low + 2 high), discarding the last quotient. 21*24 + 8 = 512.
//!
//! Unlike the SHAKE-256 / BLAKE2s constructions, this squeeze does NOT rejection-sample:
//! reducing a wide value mod Q is slightly biased. The upstream source attributes a
//! Rényi-divergence analysis bounding the loss at <= 0.37 bits to `scripts/renyi.md`,
//! a document not published with the code — the claim is reproduced here as upstream's,
//! not independently verified.
//!
//! The salt is 40 bytes (FIPS-206 length), carried as two felts of 20 bytes each — the
//! same signature grammar as `hash_to_point.cairo` (deviation: s2morrow accepts any felts).

use core::poseidon::{hades_permutation, poseidon_hash_span};

/// Each salt felt must fit in 20 bytes.
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000_u256;

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)`.
/// Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_poseidon_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }

    let seed = poseidon_hash_span(array![message_hash, salt_a, salt_b].span());
    let (mut s0, mut s1, mut s2): (felt252, felt252, felt252) = (seed, 0, 0);
    let mut coeffs: Array<u16> = array![];

    // 21 full squeeze rounds: 24 coefficients each (12 from s0, 12 from s1).
    for _ in 0..21_u32 {
        let (ns0, ns1, ns2) = hades_permutation(s0, s1, s2);
        s0 = ns0;
        s1 = ns1;
        s2 = ns2;
        extract_12(s0, ref coeffs);
        extract_12(s1, ref coeffs);
    }

    // Final round: 8 coefficients from s0 only (512 = 21*24 + 6 + 2).
    let (ns0, _, _) = hades_permutation(s0, s1, s2);
    extract_8(ns0, ref coeffs);

    Some(coeffs)
}

/// 12 base-Q digits of a felt252: 6 from the low u128, then 6 from the high part.
fn extract_12(value: felt252, ref coeffs: Array<u16>) {
    let v: u256 = value.into();
    append_digits(v.low, 6, ref coeffs);
    append_digits(v.high, 6, ref coeffs);
}

/// Final-round variant: 6 digits from the low u128, 2 from the high part.
fn extract_8(value: felt252, ref coeffs: Array<u16>) {
    let v: u256 = value.into();
    append_digits(v.low, 6, ref coeffs);
    append_digits(v.high, 2, ref coeffs);
}

/// Append `count` base-Q digits of `value` (successive remainders, LSD first); the final
/// quotient is discarded — same digit order as `packing::unpack_half`, without the
/// canonicity residue check (this is a hash squeeze, not a packed encoding).
fn append_digits(value: u128, count: u32, ref coeffs: Array<u16>) {
    let q_nz: NonZero<u128> = 12289_u128.try_into().unwrap();
    let mut rest = value;
    for _ in 0..count {
        let (quot, rem) = DivRem::div_rem(rest, q_nz);
        coeffs.append(rem.try_into().unwrap());
        rest = quot;
    }
}

#[cfg(test)]
mod tests {
    use super::{TWO_POW_160, hash_to_point_poseidon_512};

    const MSG: felt252 = 'BENCH_MSG';

    // Upstream Rust <-> Cairo cross-language known-answer vector for message=[42],
    // salt=[1, 2]: s2morrow packages/falcon/tests/data/hash_to_point_test_int.json
    // (mirrored in scripts/data/falcon_poseidon_h2p_kat.json). The full 512 coefficients
    // are pinned because a wrong extraction order scrambles the entire vector.
    const KAT_COEFFS: [u16; 512] = [
        3798, 10958, 659, 9391, 8486, 3528, 9093, 1112, 7890, 1931, 4341, 10663, 8708, 284,
        1789, 4810, 2982, 5717, 2334, 3178, 1053, 10013, 2480, 11928, 3162, 8969, 12254, 11548,
        3049, 3668, 10740, 7511, 822, 2514, 913, 4972, 1763, 10376, 10181, 4526, 11498, 4161,
        8651, 2967, 5271, 5876, 11456, 4114, 2039, 2620, 7111, 9227, 6180, 11853, 3958, 1381,
        1970, 11526, 700, 898, 11718, 10333, 4816, 12116, 2702, 5789, 3040, 3147, 3044, 11443,
        732, 3469, 4001, 2522, 7466, 12083, 5655, 9611, 3752, 4260, 5599, 4426, 9688, 12036,
        2580, 9552, 2158, 11385, 5125, 5276, 11386, 7376, 660, 2520, 3833, 6479, 8242, 6618,
        3376, 3206, 1086, 618, 9913, 6407, 2290, 153, 6625, 1958, 12286, 2266, 9919, 10972,
        7709, 11625, 4943, 6437, 4462, 7912, 3596, 8178, 9437, 176, 10725, 11257, 7588, 6542,
        7407, 1507, 10998, 5107, 11454, 957, 6466, 6886, 6448, 9097, 2642, 7577, 5856, 437,
        3515, 6527, 1553, 1714, 5511, 9174, 9312, 7126, 11273, 6698, 3334, 3790, 9782, 5271,
        5681, 4290, 8992, 4494, 5422, 10589, 714, 4600, 7487, 2645, 4983, 7477, 5889, 8361,
        11705, 4852, 7210, 10755, 9751, 9472, 2036, 9310, 8026, 9586, 3646, 8465, 9024, 2484,
        10940, 2288, 4922, 241, 8725, 3579, 3937, 317, 10767, 5658, 1321, 11359, 3640, 1457,
        1420, 11632, 7759, 11698, 10869, 5542, 2722, 3557, 172, 1255, 5850, 10570, 9626, 7773,
        2401, 1406, 9328, 4066, 5892, 4021, 8001, 2367, 1198, 823, 5532, 11344, 4755, 11462,
        164, 4667, 4885, 5829, 3213, 6501, 2739, 7985, 5480, 2882, 3871, 3180, 8625, 3562,
        5582, 4227, 5986, 3338, 3351, 5827, 9891, 2510, 304, 8209, 7556, 5381, 5093, 8243,
        11600, 8864, 2847, 1270, 11992, 1618, 5075, 5348, 864, 2008, 4215, 4307, 6241, 599,
        8712, 7345, 7270, 10008, 6548, 3207, 5546, 2273, 2707, 996, 1737, 10971, 12069, 9863,
        10069, 6794, 3241, 4938, 8338, 6310, 7233, 8977, 3032, 3550, 12065, 4841, 9578, 2564,
        5286, 4051, 7011, 11620, 7400, 4005, 4394, 4467, 11492, 1337, 6839, 10763, 2832, 10340,
        3757, 1244, 7265, 135, 5637, 11669, 145, 10574, 7424, 448, 11892, 2494, 8204, 11320,
        8245, 11959, 5720, 7346, 11809, 4872, 1962, 7322, 8944, 10664, 3509, 8373, 10872, 4661,
        10322, 7438, 6486, 5102, 7276, 10561, 2003, 10607, 2061, 2029, 3965, 9555, 4683, 5335,
        8560, 3436, 5027, 964, 3777, 11971, 6973, 4126, 5863, 10281, 10126, 11143, 7410, 2416,
        5690, 4536, 6144, 2967, 7021, 10896, 2433, 9516, 1796, 3072, 1530, 3352, 2085, 2644,
        1635, 831, 9458, 1819, 4745, 7070, 6447, 7466, 4733, 521, 4679, 6723, 1850, 12080,
        10747, 1809, 9847, 7029, 8111, 10235, 5491, 12062, 9664, 9805, 1253, 463, 980, 7928,
        4224, 10059, 9327, 3445, 580, 8275, 11906, 9966, 933, 1067, 7182, 5943, 2726, 8404,
        1103, 10408, 6339, 144, 2116, 10632, 9082, 5632, 10568, 7825, 10594, 2726, 6031, 121,
        11560, 3883, 500, 9352, 4359, 2856, 1527, 11436, 3617, 1, 9523, 5180, 4613, 8615,
        10444, 3287, 8062, 999, 4787, 5810, 5435, 11129, 11534, 10375, 2981, 6082, 2824, 9512,
        8936, 4713, 6595, 630, 7275, 7704, 1207, 5918, 4065, 11358, 9068, 2185, 37, 3894,
        901, 6684, 10256, 11815, 1382, 3963, 3466, 7504, 2170, 7255, 10512, 6948, 4233, 6905,
        10922, 9034, 8868, 3043, 9096, 3510, 8221, 3963, 5921, 2096, 557, 3090, 5000, 2846,
        4256, 1735, 9668, 9263, 587, 7974, 10252, 4685,
    ];

    #[test]
    fn test_hash_to_point_poseidon_kat() {
        let coeffs = hash_to_point_poseidon_512(42, 1, 2).unwrap();
        assert_eq!(coeffs.span(), KAT_COEFFS.span());
    }

    #[test]
    fn test_hash_to_point_poseidon_domain_separation() {
        // Different message, salt halves, or salt order all change the point, and the
        // Poseidon construction differs from the BLAKE2s one on identical inputs.
        let base = hash_to_point_poseidon_512(MSG, 1, 2).unwrap();
        let other_msg = hash_to_point_poseidon_512('OTHER_MSG', 1, 2).unwrap();
        let other_salt = hash_to_point_poseidon_512(MSG, 2, 1).unwrap();
        let blake2s = crate::hash_to_point::hash_to_point_512(MSG, 1, 2).unwrap();
        assert_ne!(base.span(), other_msg.span());
        assert_ne!(base.span(), other_salt.span());
        assert_ne!(base.span(), blake2s.span());
    }

    #[test]
    fn test_hash_to_point_poseidon_rejects_oversized_salt() {
        let too_big: felt252 = TWO_POW_160.try_into().unwrap();
        assert!(hash_to_point_poseidon_512(MSG, too_big, 0).is_none());
        assert!(hash_to_point_poseidon_512(MSG, 0, too_big).is_none());
        assert!(hash_to_point_poseidon_512(MSG, too_big - 1, too_big - 1).is_some());
    }
}
