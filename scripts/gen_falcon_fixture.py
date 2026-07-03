#!/usr/bin/env python3
"""Generate the Falcon-512 bench fixtures for crates/falcon_512.

Produces a genuine keypair and signature using the reference Falcon implementation
(github.com/tprest/falcon.py: NTRU keygen and the ffSampling trapdoor sampler), with
hash-to-point swapped from SHAKE-256 to one of the on-chain constructions (--hash):

- blake2s (default) — the counter-mode XOF of `crates/falcon_512/src/hash_to_point.cairo`:
    prefix   = salt[0:20] || salt[20:40] || message_hash.to_bytes(32, 'little')
    digest_i = blake2s-256(prefix || i.to_bytes(4, 'little'))
    candidates: the 16 LE u16 words of each digest, in order; accept c % q while c < 5q,
    until 512 coefficients.
- poseidon — s2morrow's deployed sponge squeeze of
  `crates/falcon_512/src/hash_to_point_poseidon.cairo`: seed =
  poseidon_hash_many([message_hash, salt_a, salt_b]), then 21 hades-permutation rounds
  extracting 12 base-Q digits per felt (6 low u128 + 6 high) plus a final round of 8.
  Before doing anything else in this mode, the Python mirror is checked against the
  upstream Rust<->Cairo KAT committed at scripts/data/falcon_poseidon_h2p_kat.json.

The script independently re-checks the full on-chain verification equation (hint product
via NTT, canonical packing round-trip, centered norm <= 34034726) before writing the
hash-specific fixture module (bench_fixture.cairo / bench_fixture_poseidon.cairo).

Usage:
    python3 scripts/gen_falcon_fixture.py --falcon-py /path/to/falcon.py-clone \
        [--hash blake2s|poseidon] [--force]
Dependencies (for falcon.py): numpy, pycryptodome, beartype; poseidon mode: poseidon-py.
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
OUT_FILES = {
    "blake2s": REPO / "crates/falcon_512/src/bench_fixture.cairo",
    "poseidon": REPO / "crates/falcon_512/src/bench_fixture_poseidon.cairo",
}
H2P_MODULES = {
    "blake2s": "hash_to_point.cairo",
    "poseidon": "hash_to_point_poseidon.cairo",
}
POSEIDON_KAT_FILE = REPO / "scripts/data/falcon_poseidon_h2p_kat.json"


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


def h2p_poseidon(message_hash: int, salt: bytes, n: int = 512) -> list[int]:
    """s2morrow's Poseidon hash-to-point; must match hash_to_point_poseidon.cairo exactly."""
    from poseidon_py.poseidon_hash import poseidon_hash_many, poseidon_perm

    assert len(salt) == 40
    seed = poseidon_hash_many([
        message_hash,
        int.from_bytes(salt[:20], "little"),
        int.from_bytes(salt[20:], "little"),
    ])
    out: list[int] = []

    def extract(value: int, count: int) -> None:
        for _ in range(count):
            value, digit = divmod(value, Q)
            out.append(digit)

    s0, s1, s2 = seed, 0, 0
    for _ in range(21):
        s0, s1, s2 = poseidon_perm(s0, s1, s2)
        for felt in (s0, s1):
            extract(felt & ((1 << 128) - 1), 6)
            extract(felt >> 128, 6)
    s0, _, _ = poseidon_perm(s0, s1, s2)
    extract(s0 & ((1 << 128) - 1), 6)
    extract(s0 >> 128, 2)
    assert len(out) == n
    return out


def check_poseidon_kat() -> None:
    """Gate: the Python mirror must reproduce the upstream Rust<->Cairo KAT."""
    import json

    kat = json.loads(POSEIDON_KAT_FILE.read_text())
    salt = kat["salt_a"].to_bytes(20, "little") + kat["salt_b"].to_bytes(20, "little")
    got = h2p_poseidon(kat["message_hash"], salt)
    assert got == kat["coeffs"], "poseidon mirror does not reproduce the upstream KAT"
    print(f"poseidon mirror matches upstream KAT ({POSEIDON_KAT_FILE.name})")


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
    parser.add_argument("--hash", choices=sorted(OUT_FILES), default="blake2s",
                        help="on-chain hash-to-point construction to sign against")
    parser.add_argument("--out", type=Path, default=None,
                        help="output module (default: hash-specific fixture file)")
    parser.add_argument("--force", action="store_true",
                        help="allow overwriting an existing output file")
    args = parser.parse_args()
    out_file = args.out or OUT_FILES[args.hash]
    if out_file.exists() and not args.force:
        sys.exit(f"refusing to overwrite {out_file} (committed fixture); pass --force")

    if args.hash == "poseidon":
        check_poseidon_kat()
    h2p = {"blake2s": h2p_blake2s, "poseidon": h2p_poseidon}[args.hash]

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
    point = h2p(message_hash, salt)

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

    out_file.write_text(f'''//! GENERATED by `scripts/gen_falcon_fixture.py --hash {args.hash}` — do not edit by hand.
//!
//! Falcon-512+{args.hash.upper()} bench fixture: a genuine keypair (tprest/falcon.py NTRU
//! keygen) and signature over '{MSG_LABEL}' from the reference ffSampling sampler, with
//! the {args.hash} hash-to-point of `{H2P_MODULES[args.hash]}`.
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
    print(f"wrote {out_file}")


if __name__ == "__main__":
    main()
