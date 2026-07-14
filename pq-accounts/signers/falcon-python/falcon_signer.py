#!/usr/bin/env python3
"""Falcon-512 signer for the pq-accounts CLI external-signer protocol.

One NTRU keypair serves every Falcon account variant: the variants differ only in the
hash-to-point that derives the message point, which this signer selects from the scheme
key in each request — BLAKE2s for `falcon-512` / `falcon-512-direct`, the standard
SHAKE-256 of the Falcon specification for `falcon-512-shake` / `falcon-512-shake-direct`,
and the native-Poseidon squeeze for `falcon-512-poseidon`. The `-direct` schemes return the
31-felt `s1 || salt` layout (no hint). Each construction mirrors its on-chain counterpart in
`crates/falcon_512` exactly.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pickle
import struct
import sys
from pathlib import Path
from typing import Any, Callable

Q = 12289
SIG_BOUND_512 = 34034726

# Starknet Poseidon (hades_permutation over the STARK field), vendored to match
# core::poseidon exactly: round constants are sha256("Hades"+idx), the MDS is the small
# matrix, and the schedule is 4 full + 83 partial + 4 full rounds. Verified against the
# corelib known-answer vector before every use, so no cairo-lang dependency is needed.
POSEIDON_PRIME = 2**251 + 17 * 2**192 + 1
POSEIDON_MDS = ((3, 1, 1), (1, -1, 1), (1, 1, -2))
POSEIDON_R_F, POSEIDON_R_P = 8, 83
POSEIDON_WORDS_PER_FELT = 15  # must match hash_to_point.cairo
POSEIDON_KAT = 0xFA8C9B6742B6176139365833D001E30E932A9BF7456D009B1B174F36D558C5


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


def h2p_blake2s(message_hash: int, salt: bytes, n: int = 512) -> list[int]:
    """Derive the message point with the Cairo BLAKE2s XOF construction."""
    if len(salt) != 40:
        raise ValueError("Falcon salt must be exactly 40 bytes")
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


def h2p_shake256(message_hash: int, salt: bytes, n: int = 512) -> list[int]:
    """Derive the message point with the standard Falcon SHAKE-256 hash-to-point:
    absorb salt || message, consume big-endian 16-bit words, accept `word % Q` while
    `word < 5Q`. Interoperable with falcon.py's own HashToPoint."""
    if len(salt) != 40:
        raise ValueError("Falcon salt must be exactly 40 bytes")
    shake = hashlib.shake_256(salt + message_hash.to_bytes(32, "little"))
    stream = shake.digest(4 * n)  # ample margin over the ~2n bytes expected
    out: list[int] = []
    i = 0
    while len(out) < n:
        word = (stream[i] << 8) | stream[i + 1]
        i += 2
        if word < 5 * Q:
            out.append(word % Q)
    return out


def h2p_poseidon(message_hash: int, salt: bytes, n: int = 512) -> list[int]:
    """Derive the message point with the native-Poseidon squeeze: absorb
    (salt_a, salt_b, message_hash), then read 15 low 16-bit words per rate felt,
    permuting between blocks. Matches `hash_to_point_poseidon_512`."""
    if poseidon_perm(1, 2, 3)[0] != POSEIDON_KAT:
        raise RuntimeError("vendored poseidon_perm does not match core::poseidon")
    salt_a = int.from_bytes(salt[:20], "little")
    salt_b = int.from_bytes(salt[20:], "little")
    s0, s1, s2 = poseidon_perm(salt_a, salt_b, message_hash)
    out: list[int] = []
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


# Hash-to-point construction per CLI scheme key; direct reuses the hint construction.
H2P_BY_SCHEME: dict[str, Callable[[int, bytes], list[int]]] = {
    "falcon-512": h2p_blake2s,
    "falcon-512-direct": h2p_blake2s,
    "falcon-512-shake": h2p_shake256,
    "falcon-512-shake-direct": h2p_shake256,
    "falcon-512-poseidon": h2p_poseidon,
}

# Schemes whose signature is the 31-felt `s1 || salt` prefix of the hint layout.
DIRECT_SCHEMES = {"falcon-512-direct", "falcon-512-shake-direct"}


def pack_512(vals: list[int]) -> list[int]:
    """Pack 512 base-Q coefficients into the 29-felt layout consumed on-chain."""
    if len(vals) != 512 or any(v < 0 or v >= Q for v in vals):
        raise ValueError("expected 512 coefficients in [0, q)")

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


def centered(x: int) -> int:
    """Return the centered representative modulo q."""
    return x if x <= (Q - 1) // 2 else x - Q


def as_hex(values: list[int]) -> list[str]:
    """Format felt values for Starknet.js and the CLI JSON protocol."""
    return [hex(v) for v in values]


def load_falcon_modules(falcon_py: Path) -> tuple[Any, Any, Any, Any]:
    """Load falcon.py modules from a user-provided checkout."""
    sys.path.insert(0, str(falcon_py))
    import falcon as fpy  # type: ignore
    from ntt import div_zq, mul_zq, ntt  # type: ignore

    return fpy, div_zq, mul_zq, ntt


def load_key(path: Path) -> dict[str, Any]:
    """Read the local JSON key file."""
    return json.loads(path.read_text())


def write_key(path: Path, data: dict[str, Any]) -> None:
    """Write the local JSON key file with private signing material."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def decode_private_key(data: dict[str, Any]) -> tuple[Any, list[int], list[int]]:
    """Decode the stored private key, public key polynomial, and packed public key."""
    sk = pickle.loads(base64.b64decode(data["secret_pickle_b64"]))
    h = [int(v) for v in data["h"]]
    public_key = [int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v) for v in data["public_key"]]
    return sk, h, public_key


def keygen(args: argparse.Namespace) -> None:
    """Generate a Falcon key file for the external signer. The key is hash-to-point
    agnostic: one file serves every Falcon account variant."""
    fpy, div_zq, _mul_zq, ntt = load_falcon_modules(args.falcon_py)
    scheme = fpy.Falcon(512)
    if scheme.param.sig_bound != SIG_BOUND_512:
        raise RuntimeError("unexpected Falcon-512 signature bound")

    print("keygen (NTRU solve, may take a while)...", file=sys.stderr)
    sk, _vk = scheme.keygen()
    f, g, _F, _G, _B0_fft, _T_fft = sk
    h = div_zq(g, f)
    public_key = pack_512(ntt(h))
    write_key(
        args.key,
        {
            "format": "pq-accounts-falcon-python-v1",
            "scheme": "falcon-512",
            "public_key": as_hex(public_key),
            "h": h,
            "secret_pickle_b64": base64.b64encode(pickle.dumps(sk)).decode("ascii"),
        },
    )
    print(f"wrote {args.key}", file=sys.stderr)


def sign_hash(
    message_hash: int,
    key_data: dict[str, Any],
    mul_zq: Any,
    h2p: Callable[[int, bytes], list[int]],
) -> list[int]:
    """Sign a Starknet transaction hash and return the 60-felt hint signature, deriving
    the message point with the given hash-to-point construction."""
    sk, h, _public_key = decode_private_key(key_data)
    _f, _g, _F, _G, B0_fft, T_fft = sk
    salt = os.urandom(40)
    point = h2p(message_hash, salt)

    import falcon as fpy  # type: ignore

    scheme = fpy.Falcon(512)
    if scheme.param.sig_bound != SIG_BOUND_512:
        raise RuntimeError("unexpected Falcon-512 signature bound")
    while True:
        s = scheme.__sample_preimage__(B0_fft, T_fft, point)
        norm = sum(c * c for c in s[0]) + sum(c * c for c in s[1])
        if norm <= SIG_BOUND_512:
            break

    s1 = [c % Q for c in s[1]]
    mul_hint = mul_zq(s1, h)
    # Re-check the exact on-chain acceptance condition before returning material.
    if any((s[0][i] + mul_hint[i]) % Q != point[i] for i in range(512)):
        raise RuntimeError("signer/verifier equation mismatch")
    onchain_norm = sum(
        centered((point[i] - mul_hint[i]) % Q) ** 2 + centered(s1[i]) ** 2
        for i in range(512)
    )
    if onchain_norm != norm:
        raise RuntimeError("signer/verifier norm mismatch")

    salt_a = int.from_bytes(salt[:20], "little")
    salt_b = int.from_bytes(salt[20:], "little")
    return pack_512(s1) + [salt_a, salt_b] + pack_512(mul_hint)


def request_hash(request: dict[str, Any]) -> int:
    """Extract the hash felt from a protocol request."""
    payload = request.get("payload") or {}
    value = payload.get("hash")
    if value is None:
        raise ValueError("request payload must include hash")
    return int(str(value), 0)


def protocol(args: argparse.Namespace) -> None:
    """Serve one pq-accounts external-signer JSON request."""
    _fpy, _div_zq, mul_zq, _ntt = load_falcon_modules(args.falcon_py)
    key_data = load_key(args.key)
    request = json.loads(sys.stdin.read())
    action = request.get("action")
    scheme = request.get("scheme")

    if action == "public-key":
        print(json.dumps({"publicKey": key_data["public_key"]}))
        return

    if action in {"sign-hash", "sign-transaction", "sign-deploy-account"}:
        h2p = H2P_BY_SCHEME.get(str(scheme))
        if h2p is None:
            raise ValueError(
                f"unsupported scheme: {scheme}. "
                f"Supported: {', '.join(sorted(H2P_BY_SCHEME))}"
            )
        signature = sign_hash(request_hash(request), key_data, mul_zq, h2p)
        if scheme in DIRECT_SCHEMES:
            signature = signature[:31]
        print(json.dumps({"signature": as_hex(signature)}))
        return

    raise ValueError(f"unsupported action: {action}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    keygen_parser = subparsers.add_parser("keygen", help="generate a local Falcon key file")
    keygen_parser.add_argument("--falcon-py", type=Path, required=True, help="path to a falcon.py checkout")
    keygen_parser.add_argument("--key", type=Path, required=True, help="key file to write")

    parser.add_argument("--falcon-py", type=Path, help="path to a falcon.py checkout")
    parser.add_argument("--key", type=Path, help="key file to read")
    args = parser.parse_args()

    if args.command == "keygen":
        keygen(args)
        return

    if args.falcon_py is None or args.key is None:
        parser.error("protocol mode requires --falcon-py and --key")
    protocol(args)


if __name__ == "__main__":
    main()
