//! Operations on the base ring Z_q (q = 12289).
//!
//! Coefficients are `u16` values in `[0, Q)` by construction — every function returns a
//! `% Q` result — with u32/u64 intermediates sized so the arithmetic cannot overflow.

/// The Falcon modulus q = 12289 = 12·1024 + 1.
pub const Q: u16 = 12289;
pub const Q32: u32 = 12289;
pub const Q64: u64 = 12289;

/// Largest centered-low value: (Q-1)/2. Coefficients above this represent negatives.
pub const Q_HALF: u16 = 6144;

/// Add two values modulo Q.
#[inline(always)]
pub fn add_mod(a: u16, b: u16) -> u16 {
    // a, b < Q so a + b <= 24576 < 2^16: the checked u16 add never overflows, and a
    // single conditional subtraction reduces the sum.
    let d = a + b;
    if d >= Q {
        d - Q
    } else {
        d
    }
}

/// Subtract two values modulo Q, via a + Q - b and one conditional subtraction.
#[inline(always)]
pub fn sub_mod(a: u16, b: u16) -> u16 {
    // a < Q so a + Q <= 24577 < 2^16; a + Q - b is in [1, 2Q-1].
    let d = a + Q - b;
    if d >= Q {
        d - Q
    } else {
        d
    }
}

/// Multiply two values modulo Q.
#[inline(always)]
pub fn mul_mod(a: u16, b: u16) -> u16 {
    let a: u32 = a.into();
    let b: u32 = b.into();
    // a·b <= 12288² < 2^31.
    let res = (a * b) % Q32;
    res.try_into().unwrap()
}

/// Squared centered representative of a coefficient, as felt252:
/// x ∈ [0, 6144] → x²; x ∈ [6145, 12288] → (Q - x)².
#[inline(always)]
pub fn center_sq(coeff: u16) -> felt252 {
    if coeff <= Q_HALF {
        let x: felt252 = coeff.into();
        x * x
    } else {
        let x: felt252 = (Q - coeff).into();
        x * x
    }
}

#[cfg(test)]
mod tests {
    use super::{Q, add_mod, center_sq, mul_mod, sub_mod};

    #[test]
    fn test_add_mod_wraps() {
        assert_eq!(add_mod(12288, 1), 0);
        assert_eq!(add_mod(12288, 12288), 12287); // (-1) + (-1) = -2 = q - 2
        assert_eq!(add_mod(0, 0), 0);
    }

    #[test]
    fn test_sub_mod_wraps() {
        assert_eq!(sub_mod(0, 1), 12288);
        assert_eq!(sub_mod(1, 1), 0);
        assert_eq!(sub_mod(12288, 12287), 1);
    }

    #[test]
    fn test_mul_mod() {
        assert_eq!(mul_mod(12288, 12288), 1); // (-1)² = 1
        assert_eq!(mul_mod(0, 12288), 0);
        // SQR1 = 1479 is a square root of -1 mod q
        assert_eq!(mul_mod(1479, 1479), Q - 1);
        // 2 · 6145 = 12290 = 1 mod q (6145 = 2⁻¹)
        assert_eq!(mul_mod(2, 6145), 1);
    }

    #[test]
    fn test_center_sq() {
        assert_eq!(center_sq(0), 0);
        assert_eq!(center_sq(1), 1);
        assert_eq!(center_sq(6144), 6144 * 6144); // largest low-half value
        assert_eq!(center_sq(6145), 6144 * 6144); // q - 6145 = 6144
        assert_eq!(center_sq(12288), 1); // -1 centered is ±1
    }

    // Probe retained from the port plan: `[u16; N]` const tables are the format the
    // generated NTT root tables use.
    const PROBE_TABLE: [u16; 3] = [0, 6144, 12288];

    #[test]
    fn test_const_u16_table() {
        let t = PROBE_TABLE.span();
        assert_eq!(*t.at(0), 0);
        assert_eq!(*t.at(1), 6144);
        assert_eq!(*t.at(2), 12288);
    }
}
