#!/usr/bin/env python3
"""Falcon-512 signer for the pq-accounts CLI external-signer protocol."""

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
from typing import Any

Q = 12289
SIG_BOUND_512 = 34034726


def h2p_blake2s(message_hash: int, salt: bytes, n: int = 512) -> list[int]:
    """Derive the verifier message point with the Cairo BLAKE2s XOF construction."""
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
    """Generate a Falcon key file for the external signer."""
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
            "scheme": "falcon-512-blake2s",
            "public_key": as_hex(public_key),
            "h": h,
            "secret_pickle_b64": base64.b64encode(pickle.dumps(sk)).decode("ascii"),
        },
    )
    print(f"wrote {args.key}", file=sys.stderr)


def sign_hash(message_hash: int, key_data: dict[str, Any], mul_zq: Any) -> list[int]:
    """Sign a Starknet transaction hash and return the 60-felt hint signature."""
    sk, h, _public_key = decode_private_key(key_data)
    _f, _g, _F, _G, B0_fft, T_fft = sk
    scheme_bound = SIG_BOUND_512
    salt = os.urandom(40)
    point = h2p_blake2s(message_hash, salt)

    import falcon as fpy  # type: ignore

    scheme = fpy.Falcon(512)
    while True:
        s = scheme.__sample_preimage__(B0_fft, T_fft, point)
        norm = sum(c * c for c in s[0]) + sum(c * c for c in s[1])
        if norm <= scheme_bound:
            break

    s1 = [c % Q for c in s[1]]
    mul_hint = mul_zq(s1, h)
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
        signature = sign_hash(request_hash(request), key_data, mul_zq)
        if scheme == "falcon-512-direct":
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
