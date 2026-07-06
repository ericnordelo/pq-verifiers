//! SHAKE-256 extendable-output function (FIPS 202), implemented in pure Cairo.
//!
//! Written from the FIPS 202 specification (Keccak-f[1600] sponge, rate 1088 bits =
//! 136 bytes, capacity 512, domain-separation `0x1F`, pad10*1). Starknet exposes no
//! SHAKE primitive and its `keccak` syscall bakes in keccak256's `0x01` padding and a
//! fixed 256-bit output, so neither is reusable here; the permutation is implemented
//! directly. A future `keccak_f1600` syscall (SNIP-32) would replace `keccak_f1600`
//! and collapse the cost.
//!
//! State: 25 lanes of 64 bits, `lane[x + 5y]`, bytes mapped little-endian per lane.
//!
//! Performance (the permutation dominates on-chain cost, so it is written tight):
//! - `rotl` is division-free: rotation amounts are pre-exponentiated to `2^r`, so a
//!   left-rotate is one `u128` multiply and one `div_rem` by `2^64` (`hi | lo`), avoiding
//!   the two `u64` divisions a shift-pair would cost.
//! - each round builds only two 25-lane arrays: θ is fused into the ρ+π pass (no separate
//!   θ array), and ι is folded into the χ pass (no separate output array).
//! The permutation tables (`2^rho`, the inverse-π map, round constants) are built once per
//! call and threaded in. What remains is inherent to a software Keccak-f[1600].

const MASK64: u64 = 0xffffffffffffffff;
const RATE_LANES: u32 = 17; // 136 bytes / 8
const RATE_BYTES: u32 = 136;

/// Keccak-f[1600] round constants (FIPS 202, Table 1).
fn round_constants() -> Span<u64> {
    [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
        .span()
}

/// For each ρ+π destination lane `d`, the source lane it reads: `b[d]` is built from
/// `theta[PI_INV[d]]`. Derived from `pi(x,y)=(y, 2x+3y)`, precomposed so the round is a
/// single in-order pass.
fn pi_inv() -> Span<u32> {
    [0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21]
        .span()
}

/// The ρ rotation applied at each destination lane (FIPS 202 ρ offsets, reordered to match
/// `PI_INV`), used to index the power-of-two table into the `2^rho` factors.
fn rho_by_dest() -> Span<u32> {
    [0, 44, 43, 21, 14, 28, 20, 3, 45, 61, 1, 6, 25, 8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41, 2]
        .span()
}

/// Powers of two `2^n` for n in 0..=64, built once per hash.
fn pow2_table() -> Array<u128> {
    let mut t: Array<u128> = array![];
    let mut v: u128 = 1;
    let mut i = 0;
    while i != 65 {
        t.append(v);
        v = v * 2;
        i += 1;
    }
    t
}

/// Rotate a 64-bit lane left, given `pow = 2^n` with 0 <= n < 64. The widened product
/// `x * 2^n < 2^128` splits at bit 64 into the bits that stay (`lo`) and the bits that wrap
/// to the bottom (`hi`); they occupy disjoint positions, so `lo + hi` is the rotation.
#[inline(always)]
fn rotl_pow(x: u64, pow: u128, two64: NonZero<u128>) -> u64 {
    let (hi, lo) = DivRem::div_rem(x.into() * pow, two64);
    (lo + hi).try_into().unwrap()
}

/// One Keccak-f[1600] round on the 25-lane state.
fn keccak_round(
    a: @Array<u64>, rc: u64, piv: Span<u32>, pow_rbd: @Array<u128>, two64: NonZero<u128>,
) -> Array<u64> {
    // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
    let c0 = *a[0] ^ *a[5] ^ *a[10] ^ *a[15] ^ *a[20];
    let c1 = *a[1] ^ *a[6] ^ *a[11] ^ *a[16] ^ *a[21];
    let c2 = *a[2] ^ *a[7] ^ *a[12] ^ *a[17] ^ *a[22];
    let c3 = *a[3] ^ *a[8] ^ *a[13] ^ *a[18] ^ *a[23];
    let c4 = *a[4] ^ *a[9] ^ *a[14] ^ *a[19] ^ *a[24];
    let dcol = array![
        c4 ^ rotl_pow(c1, 2, two64), c0 ^ rotl_pow(c2, 2, two64), c1 ^ rotl_pow(c3, 2, two64),
        c2 ^ rotl_pow(c4, 2, two64), c3 ^ rotl_pow(c0, 2, two64),
    ];

    // theta (fused) + rho + pi: write b straight into destination order.
    let mut b: Array<u64> = array![];
    let mut dst = 0;
    while dst != 25 {
        let src = *piv[dst];
        let theta_src = *a[src] ^ *dcol[src % 5];
        b.append(rotl_pow(theta_src, *pow_rbd[dst], two64));
        dst += 1;
    }

    // chi, with iota (rc) folded into lane 0 (the first lane emitted).
    let mut out: Array<u64> = array![];
    let mut y = 0;
    while y != 5 {
        let r = 5 * y;
        let b0 = *b[r];
        let b1 = *b[r + 1];
        let b2 = *b[r + 2];
        let b3 = *b[r + 3];
        let b4 = *b[r + 4];
        let lane0 = b0 ^ ((b1 ^ MASK64) & b2);
        out.append(if y == 0 {
            lane0 ^ rc
        } else {
            lane0
        });
        out.append(b1 ^ ((b2 ^ MASK64) & b3));
        out.append(b2 ^ ((b3 ^ MASK64) & b4));
        out.append(b3 ^ ((b4 ^ MASK64) & b0));
        out.append(b4 ^ ((b0 ^ MASK64) & b1));
        y += 1;
    }
    out
}

fn keccak_f1600(
    state: Array<u64>, rc: Span<u64>, piv: Span<u32>, pow_rbd: @Array<u128>, two64: NonZero<u128>,
) -> Array<u64> {
    let mut s = state;
    let mut r = 0;
    while r != 24 {
        s = keccak_round(@s, *rc[r], piv, pow_rbd, two64);
        r += 1;
    }
    s
}

fn zeros25() -> Array<u64> {
    let mut s: Array<u64> = array![];
    let mut i = 0;
    while i != 25 {
        s.append(0);
        i += 1;
    }
    s
}

/// SHAKE-256: absorb `input`, squeeze `out_bytes` bytes.
pub fn shake256(input: Array<u8>, out_bytes: u32) -> Array<u8> {
    // Permutation tables, built once and threaded through every round.
    let two64: NonZero<u128> = 0x10000000000000000_u128.try_into().unwrap();
    let rc = round_constants();
    let piv = pi_inv();
    let rbd = rho_by_dest();
    let p2 = pow2_table();
    let mut pow_rbd: Array<u128> = array![]; // 2^rho, in destination order
    let mut t = 0;
    while t != 25 {
        pow_rbd.append(*p2[*rbd[t]]);
        t += 1;
    }

    // Pad (pad10*1 with SHAKE domain 0x1F) to a multiple of the rate.
    let mut padded = input;
    let l = padded.len();
    let pad_len = RATE_BYTES - (l % RATE_BYTES); // in [1, RATE_BYTES]
    padded.append(0x1f);
    let mut z = 1;
    while z != pad_len {
        padded.append(0);
        z += 1;
    }
    let last_idx = l + pad_len - 1;
    let bytes = pad_ored_msb(padded, last_idx);

    // Absorb rate-sized blocks.
    let mut state = zeros25();
    let n_blocks = (l + pad_len) / RATE_BYTES;
    let mut blk = 0;
    while blk != n_blocks {
        let base = blk * RATE_BYTES;
        let mut ns: Array<u64> = array![];
        let mut lane = 0;
        while lane != 25 {
            if lane < RATE_LANES {
                ns.append(*state[lane] ^ load_lane_le(@bytes, base + lane * 8));
            } else {
                ns.append(*state[lane]);
            }
            lane += 1;
        }
        state = keccak_f1600(ns, rc, piv, @pow_rbd, two64);
        blk += 1;
    }

    // Squeeze rate-sized blocks.
    let mut out: Array<u8> = array![];
    while out.len() < out_bytes {
        let mut lane = 0;
        while lane != RATE_LANES && out.len() < out_bytes {
            emit_lane_le(*state[lane], ref out, out_bytes);
            lane += 1;
        }
        if out.len() < out_bytes {
            state = keccak_f1600(state, rc, piv, @pow_rbd, two64);
        }
    }
    out
}

/// Append up to 8 little-endian bytes of `v`, stopping at `out_bytes`.
fn emit_lane_le(v: u64, ref out: Array<u8>, out_bytes: u32) {
    let mut rem = v;
    let mut k = 0;
    while k != 8 && out.len() < out_bytes {
        out.append((rem % 256).try_into().unwrap());
        rem = rem / 256;
        k += 1;
    }
}

/// Rebuild `bytes` with `bytes[idx] |= 0x80` (that byte is < 0x80 here, so `+ 0x80`).
fn pad_ored_msb(bytes: Array<u8>, idx: u32) -> Array<u8> {
    let mut out: Array<u8> = array![];
    let span = bytes.span();
    let mut i = 0;
    while i != span.len() {
        if i == idx {
            out.append(*span[i] + 0x80);
        } else {
            out.append(*span[i]);
        }
        i += 1;
    }
    out
}

/// Little-endian u64 from 8 bytes at `off`.
fn load_lane_le(bytes: @Array<u8>, off: u32) -> u64 {
    let span = bytes.span();
    let mut acc: u64 = 0;
    let mut k = 8;
    while k != 0 {
        k -= 1;
        acc = acc * 256 + (*span[off + k]).into();
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::shake256;

    fn to_hex(bytes: Array<u8>) -> ByteArray {
        let hexchars: ByteArray = "0123456789abcdef";
        let mut s: ByteArray = "";
        let mut span = bytes.span();
        while let Some(b) = span.pop_front() {
            s.append_byte(hexchars.at((*b / 16).into()).unwrap());
            s.append_byte(hexchars.at((*b % 16).into()).unwrap());
        }
        s
    }

    // KAT vectors from Python `hashlib.shake_256` (FIPS 202).
    #[test]
    fn test_shake256_empty() {
        let got = to_hex(shake256(array![], 32));
        assert!(got == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    }

    #[test]
    fn test_shake256_abc() {
        let got = to_hex(shake256(array![0x61, 0x62, 0x63], 32));
        assert!(got == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
    }

    // 200 bytes of 0xA3: a 2-block absorb (input > 136-byte rate). NIST SHAKE-256 vector.
    #[test]
    fn test_shake256_multiblock() {
        let mut input: Array<u8> = array![];
        let mut i = 0;
        while i != 200_u32 {
            input.append(0xa3);
            i += 1;
        }
        let got = to_hex(shake256(input, 32));
        assert!(got == "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d");
    }
}
