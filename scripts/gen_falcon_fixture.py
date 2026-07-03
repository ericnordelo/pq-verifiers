#!/usr/bin/env python3
"""Generate the Falcon-512+BLAKE2s bench fixture for crates/falcon_512.

Produces a genuine keypair and signature using the reference Falcon implementation
(github.com/tprest/falcon.py: NTRU keygen and the ffSampling trapdoor sampler), with
hash-to-point swapped from SHAKE-256 to the BLAKE2s counter-mode construction implemented
on-chain in `crates/falcon_512/src/hash_to_point.cairo`:

    prefix   = salt[0:20] || salt[20:40] || message_hash.to_bytes(32, 'little')
    digest_i = blake2s-256(prefix || i.to_bytes(4, 'little'))
    candidates: the 16 LE u16 words of each digest, in order; accept c % q while c < 5q,
    until 512 coefficients.

The script independently re-checks the full on-chain verification equation (hint product
via NTT, canonical packing round-trip, centered norm <= 34034726) before writing
`crates/falcon_512/src/bench_fixture.cairo`.

Usage:
    python3 scripts/gen_falcon_fixture.py --falcon-py /path/to/falcon.py-clone
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
OUT_FILE = REPO / "crates/falcon_512/src/bench_fixture.cairo"


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--falcon-py", type=Path, required=True,
                        help="path to a github.com/tprest/falcon.py clone")
    parser.add_argument("--out", type=Path, default=OUT_FILE)
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
    point = h2p_blake2s(message_hash, salt)

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

    args.out.write_text(f'''//! GENERATED by `scripts/gen_falcon_fixture.py` — do not edit by hand.
//!
//! Falcon-512+BLAKE2s bench fixture: a genuine keypair (tprest/falcon.py NTRU keygen)
//! and signature over '{MSG_LABEL}' from the reference ffSampling sampler, with the
//! BLAKE2s hash-to-point of `hash_to_point.cairo`.
//! salt = 0x{salt.hex()}, ||s0||^2 + ||s1||^2 = {norm} (bound {SIG_BOUND_512}).

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
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
