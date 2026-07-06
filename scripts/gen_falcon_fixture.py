#!/usr/bin/env python3
"""Generate the Falcon-512 bench fixtures for crates/falcon_512.

Two hash-to-point variants, selected with --variant:

  blake2s (default) -> crates/falcon_512/src/fixtures/blake.cairo
      Non-standard BLAKE2s counter-mode hash-to-point (matching hash_to_point.cairo).
      falcon.py has no BLAKE2s mode, so the construction is reimplemented here
      (h2p_blake2s) and the reference sampler signs the resulting point.

  shake -> crates/falcon_512/src/fixtures/shake.cairo
      Standard SHAKE-256 hash-to-point (FIPS 206), taken directly from falcon.py's own
      __hash_to_point__: the fixture is a genuine standards-compliant Falcon signature,
      interoperable with any compliant signer. Matches hash_to_point_shake_512.

  poseidon -> crates/falcon_512/src/fixtures/poseidon.cairo
      Non-standard native-Poseidon squeeze (matching hash_to_point_poseidon_512). Uses a
      small vendored Poseidon permutation (poseidon_perm) that reproduces Starknet's
      core::poseidon exactly (checked against its known-answer vector at run time), so no
      extra dependency is required.

All variants use a genuine keypair (github.com/tprest/falcon.py NTRU keygen) and the
reference ffSampling trapdoor sampler, and both re-check the full on-chain verification
equation (hint product via NTT, canonical packing round-trip, centered norm <= 34034726)
before writing.

Usage:
    python3 scripts/gen_falcon_fixture.py --falcon-py /path/to/falcon.py-clone [--variant shake]
Dependencies (for falcon.py): numpy, pycryptodome, beartype.
"""

import argparse
import hashlib
import os
import struct
import sys
from pathlib import Path

Q = 12289
SIG_BOUND_512 = 34034726
MSG_LABEL = "BENCH_MSG"

REPO = Path(__file__).resolve().parent.parent
OUT_FILE = REPO / "crates/falcon_512/src/fixtures/blake.cairo"
OUT_FILE_SHAKE = REPO / "crates/falcon_512/src/fixtures/shake.cairo"
OUT_FILE_POSEIDON = REPO / "crates/falcon_512/src/fixtures/poseidon.cairo"

# Starknet Poseidon (hades_permutation over the STARK field), vendored to match
# core::poseidon exactly: round constants are sha256("Hades"+idx), the MDS is the small
# matrix, and the schedule is 4 full + 83 partial + 4 full rounds. Verified against the
# corelib known-answer vector in main(). Vendored (rather than imported) so the generator
# needs no cairo-lang dependency; the on-chain side uses the native builtin.
POSEIDON_PRIME = 2**251 + 17 * 2**192 + 1
POSEIDON_MDS = ((3, 1, 1), (1, -1, 1), (1, 1, -2))
POSEIDON_R_F, POSEIDON_R_P = 8, 83
POSEIDON_WORDS_PER_FELT = 15  # must match hash_to_point.cairo


def _hades_ark(idx: int) -> int:
    return int(hashlib.sha256(f"Hades{idx}".encode()).hexdigest(), 16) % POSEIDON_PRIME


def poseidon_perm(s0: int, s1: int, s2: int) -> tuple:
    """Starknet hades_permutation on 3 field elements; matches core::poseidon."""
    st = [s0 % POSEIDON_PRIME, s1 % POSEIDON_PRIME, s2 % POSEIDON_PRIME]

    def rnd(st: list, ridx: int, full: bool) -> list:
        st = [(st[j] + _hades_ark(3 * ridx + j)) % POSEIDON_PRIME for j in range(3)]
        if full:
            st = [pow(x, 3, POSEIDON_PRIME) for x in st]
        else:
            st[2] = pow(st[2], 3, POSEIDON_PRIME)
        return [sum(POSEIDON_MDS[i][k] * st[k] for k in range(3)) % POSEIDON_PRIME
                for i in range(3)]

    ridx = 0
    for _ in range(POSEIDON_R_F // 2):
        st = rnd(st, ridx, True)
        ridx += 1
    for _ in range(POSEIDON_R_P):
        st = rnd(st, ridx, False)
        ridx += 1
    for _ in range(POSEIDON_R_F // 2):
        st = rnd(st, ridx, True)
        ridx += 1
    return st[0], st[1], st[2]


def h2p_poseidon(message_hash: int, salt_a: int, salt_b: int, n: int = 512) -> list:
    """Poseidon-squeeze hash-to-point; must match hash_to_point_poseidon_512 exactly.

    Absorb (salt_a, salt_b, message_hash) with one permutation, then squeeze the two rate
    elements (s0, s1) 15 low 16-bit words at a time, permuting between blocks.
    """
    s0, s1, s2 = poseidon_perm(salt_a, salt_b, message_hash)
    out: list = []
    while len(out) < n:
        for felt in (s0, s1):
            for j in range(POSEIDON_WORDS_PER_FELT):
                if len(out) < n:
                    word = (felt >> (16 * j)) & 0xFFFF
                    if word < 5 * Q:
                        out.append(word % Q)
        if len(out) < n:
            s0, s1, s2 = poseidon_perm(s0, s1, s2)
    return out


def h2p_blake2s(message_hash: int, salt: bytes, n: int = 512) -> list[int]:
    """The BLAKE2s hash-to-point; must match hash_to_point.cairo exactly."""
    assert len(salt) == 40
    prefix = salt + message_hash.to_bytes(32, "little")
    out: list[int] = []
    ctr = 0
    while len(out) < n:
        digest = hashlib.blake2s(prefix + ctr.to_bytes(4, "little")).digest()
        for cand in struct.unpack("<16H", digest):
            if len(out) < n and cand < 5 * Q:
                out.append(cand % Q)
        ctr += 1
    return out


def pack_512(vals: list[int]) -> list[int]:
    """Base-Q packing; must match packing.cairo: felt = pack9(lo) + 2^128 * pack9(hi)."""
    assert len(vals) == 512 and all(0 <= v < Q for v in vals)

    def pack_half(chunk: list[int]) -> int:
        acc = 0
        for c in reversed(chunk):
            acc = acc * Q + c
        return acc

    felts = []
    for j in range(28):
        lo = pack_half(vals[18 * j : 18 * j + 9])
        hi = pack_half(vals[18 * j + 9 : 18 * j + 18])
        felts.append(lo + (hi << 128))
    felts.append(pack_half(vals[504:512]))
    return felts


def unpack_512(felts: list[int]) -> list[int]:
    """Inverse of pack_512, with the same canonicity checks as packing.cairo."""
    assert len(felts) == 29
    vals: list[int] = []
    for j, felt in enumerate(felts):
        lo, hi = felt & ((1 << 128) - 1), felt >> 128
        halves = [(lo, 8)] if j == 28 else [(lo, 9), (hi, 9)]
        if j == 28:
            assert hi == 0, "non-canonical last slot"
        for value, count in halves:
            for _ in range(count):
                value, digit = divmod(value, Q)
                vals.append(digit)
            assert value == 0, "non-canonical half"
    return vals


def centered(x: int) -> int:
    return x if x <= (Q - 1) // 2 else x - Q


def emit_fixture(mods, sk, h, h_ntt, message_hash, point, salt, out_path, header):
    """Sample a signature over `point`, re-check the on-chain equation, and write the
    fixture. `mods` bundles the falcon.py sampler and the ntt helpers; `header` is the
    generated file's `//!` doc block. Returns the achieved squared norm."""
    scheme, mul_zq, ntt = mods
    _, _, _, _, B0_fft, T_fft = sk

    print("sampling signature...")
    while True:
        s = scheme.__sample_preimage__(B0_fft, T_fft, point)
        norm = sum(c * c for c in s[0]) + sum(c * c for c in s[1])
        if norm <= SIG_BOUND_512:
            break
        print(f"  norm {norm} > bound, resampling")

    s1 = [c % Q for c in s[1]]
    s0 = [c % Q for c in s[0]]
    mul_hint = mul_zq(s1, h)

    # Re-check the exact on-chain verification equation, independently of the sampler.
    assert all((s0[i] + mul_hint[i]) % Q == point[i] for i in range(512)), \
        "verification equation s0 + s1*h == point violated"
    s1_ntt, hint_ntt = ntt(s1), ntt(mul_hint)
    assert all(s1_ntt[i] * h_ntt[i] % Q == hint_ntt[i] for i in range(512)), \
        "hint product check violated"
    onchain_norm = sum(
        centered((point[i] - mul_hint[i]) % Q) ** 2 + centered(s1[i]) ** 2
        for i in range(512)
    )
    assert onchain_norm == norm <= SIG_BOUND_512, "centered norm mismatch"

    pk_felts = pack_512(h_ntt)
    s1_felts = pack_512(s1)
    hint_felts = pack_512(mul_hint)
    salt_a = int.from_bytes(salt[:20], "little")
    salt_b = int.from_bytes(salt[20:], "little")
    assert unpack_512(pk_felts) == h_ntt
    assert unpack_512(s1_felts) == s1
    assert unpack_512(hint_felts) == mul_hint

    signature = s1_felts + [salt_a, salt_b] + hint_felts
    print(f"norm = {norm} (bound {SIG_BOUND_512}), salt = {salt.hex()}")

    def felt_lines(felts: list[int]) -> str:
        return "\n".join(f"        {hex(v)}," for v in felts)

    out_path.write_text(f'''{header}

/// The benchmark message hash ('{MSG_LABEL}').
pub fn msg() -> felt252 {{
    {message_hash}
}}

/// Packed NTT-domain public key h ({len(pk_felts)} felts).
pub fn public_key() -> Array<felt252> {{
    array![
{felt_lines(pk_felts)}
    ]
}}

/// Signature: packed s1 (29 felts) || salt (2 felts) || packed mul_hint (29 felts).
pub fn signature() -> Array<felt252> {{
    array![
{felt_lines(signature)}
    ]
}}
''')
    print(f"wrote {out_path}")
    return norm


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--falcon-py", type=Path, required=True,
                        help="path to a github.com/tprest/falcon.py clone")
    parser.add_argument("--variant", choices=("blake2s", "shake", "poseidon"),
                        default="blake2s", help="hash-to-point construction (default: blake2s)")
    parser.add_argument("--out", type=Path, default=None,
                        help="output path (defaults to the variant's bench fixture)")
    args = parser.parse_args()

    sys.path.insert(0, str(args.falcon_py))
    import falcon as fpy  # noqa: E402
    from ntt import div_zq, mul_zq, ntt  # noqa: E402

    scheme = fpy.Falcon(512)
    assert scheme.param.sig_bound == SIG_BOUND_512

    print("keygen (NTRU solve, may take a while)...")
    sk, _vk = scheme.keygen()
    f, g, F, G, B0_fft, T_fft = sk
    h = div_zq(g, f)  # public key polynomial: h*f = g mod (q, x^512+1)
    h_ntt = ntt(h)

    message_hash = int.from_bytes(MSG_LABEL.encode(), "big")
    salt = os.urandom(40)
    mods = (scheme, mul_zq, ntt)

    if args.variant == "shake":
        # falcon.py's own SHAKE-256 hash-to-point over salt || message (FIPS 206).
        message_bytes = message_hash.to_bytes(32, "little")
        point = scheme.__hash_to_point__(message_bytes, salt)
        out_path = args.out or OUT_FILE_SHAKE
        header = (
            "//! GENERATED by `scripts/gen_falcon_fixture.py --variant shake` "
            "— do not edit by hand.\n"
            "//!\n"
            "//! Falcon-512 bench fixture with the STANDARD SHAKE-256 hash-to-point "
            "(FIPS 206):\n"
            "//! a genuine keypair (tprest/falcon.py NTRU keygen) and a "
            "standards-compliant\n"
            f"//! signature over '{MSG_LABEL}' from the reference ffSampling sampler, "
            "using falcon.py's\n"
            "//! own __hash_to_point__ (matching `hash_to_point_shake_512`).\n"
            f"//! salt = 0x{salt.hex()}."
        )
    elif args.variant == "poseidon":
        salt_a = int.from_bytes(salt[:20], "little")
        salt_b = int.from_bytes(salt[20:], "little")
        # Sanity: the vendored permutation reproduces core::poseidon's KAT vector.
        assert poseidon_perm(1, 2, 3)[0] == (
            0xfa8c9b6742b6176139365833d001e30e932a9bf7456d009b1b174f36d558c5
        ), "vendored poseidon_perm does not match core::poseidon"
        point = h2p_poseidon(message_hash, salt_a, salt_b)
        out_path = args.out or OUT_FILE_POSEIDON
        header = (
            "//! GENERATED by `scripts/gen_falcon_fixture.py --variant poseidon` "
            "— do not edit by hand.\n"
            "//!\n"
            "//! Falcon-512 bench fixture with the native-POSEIDON hash-to-point:\n"
            "//! a genuine keypair (tprest/falcon.py NTRU keygen) and signature over "
            f"'{MSG_LABEL}' from the\n"
            "//! reference ffSampling sampler, with a Poseidon squeeze "
            "(matching `hash_to_point_poseidon_512`).\n"
            f"//! salt = 0x{salt.hex()}."
        )
    else:
        point = h2p_blake2s(message_hash, salt)
        out_path = args.out or OUT_FILE
        header = (
            "//! GENERATED by `scripts/gen_falcon_fixture.py` — do not edit by hand.\n"
            "//!\n"
            "//! Falcon-512+BLAKE2s bench fixture: a genuine keypair (tprest/falcon.py "
            "NTRU keygen)\n"
            f"//! and signature over '{MSG_LABEL}' from the reference ffSampling sampler, "
            "with the\n"
            "//! BLAKE2s hash-to-point (matching `hash_to_point_512`).\n"
            f"//! salt = 0x{salt.hex()}."
        )

    emit_fixture(mods, sk, h, h_ntt, message_hash, point, salt, out_path, header)


if __name__ == "__main__":
    main()
