//! Base-Q coefficient packing: 512 `Z_q` coefficients <-> felt252 slots,
//! 18 coefficients per felt (Horner, base q = 12289), 29 felts total
//! (28 x 18 + 1 x 8). Unpacking enforces canonicality: every extracted digit is
//! < q by construction, and the leftover quotient MUST be zero — this is the
//! "public-key coefficients < Q on read" check the reference implementation was
//! missing (see PORTING.md, audit note).

const Q: u256 = 12289;

/// Unpack exactly 512 coefficients from 29 base-Q-packed felts.
/// Panics (rejects) on a non-canonical encoding.
pub fn unpack_512(felts: Span<felt252>) -> Array<u16> {
    let mut out: Array<u16> = array![];
    let mut fi: u32 = 0;
    while fi != felts.len() {
        let mut x: u256 = (*felts.at(fi)).into();
        let remaining = 512 - out.len();
        let take = if remaining < 18 {
            remaining
        } else {
            18
        };
        let mut j: u32 = 0;
        while j != take {
            let digit = x % Q;
            x = x / Q;
            out.append(digit.try_into().unwrap());
            j += 1;
        }
        assert!(x == 0, "non-canonical packing");
        fi += 1;
    }
    out
}
