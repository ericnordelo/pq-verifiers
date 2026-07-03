#!/usr/bin/env python3
"""Independently verify the NTT root tables in crates/ntt/src/roots.cairo.

The tables were ported verbatim from s2morrow (starkware-bitcoin/s2morrow@831bb518b06d).
This script re-derives their defining properties from first principles instead of
trusting the port:

  1. inverse tables pair entrywise with the forward tables: root * inv = 1 (mod q);
  2. root-chain consistency: each degree-n table entry squares to the corresponding
     degree-n/2 evaluation point, terminating at the roots of x^2 + 1 (1479^2 = -1);
  3. every degree-n evaluation point p satisfies p^n = -1 (mod q) and all n points are
     distinct, i.e. the NTT is evaluation at the n primitive 2n-th roots of unity
     (hence a bijection);
  4. a Python reimplementation of the split/merge NTT using the extracted tables matches
     direct per-point Horner evaluation, and INTT(NTT(f)) == f, on random inputs;
  5. optionally (--falcon-py PATH to a github.com/tprest/falcon.py clone): the tables
     equal the even entries of falcon.py's roots_dict_Zq, and NTT outputs match
     falcon.py's ntt() exactly — pinning the interop convention used by off-chain
     signers, including the [1, 2, ..., 512] known-answer vector in the Cairo tests.

Exits non-zero on any mismatch.
"""

import argparse
import random
import re
import sys
from pathlib import Path

Q = 12289
SQR1 = 1479  # square root of -1 mod q; the two roots of x^2 + 1 are +-SQR1
I2 = 6145  # inverse of 2 mod q
DEGREES = [4, 8, 16, 32, 64, 128, 256, 512]

CAIRO_FILE = Path(__file__).resolve().parent.parent / "crates/ntt/src/roots.cairo"

# degree n (output size of merge_ntt) -> Cairo const holding its n/2 merge roots;
# the tables are named after the cyclotomic phi_{2n} = x^n + 1 they are roots of.
FWD_NAME = {n: f"phi{2 * n}_roots_zq" for n in [2] + DEGREES}
INV_NAME = {n: f"phi{2 * n}_roots_zq_inv" for n in [2] + DEGREES}


def parse_tables(path):
    src = path.read_text()
    tables = {}
    for m in re.finditer(
        r"const\s+(\w+):\s*\[u16;\s*(\d+)\]\s*=\s*\[([^\]]*)\];", src, re.DOTALL
    ):
        name, size, body = m.group(1), int(m.group(2)), m.group(3)
        values = [int(v) for v in re.findall(r"\d+", body)]
        assert len(values) == size, f"{name}: declared [u16; {size}], found {len(values)}"
        tables[name] = values
    return tables


def check_inverse_pairing(tables):
    for n in [2] + DEGREES:
        fwd, inv = tables[FWD_NAME[n]], tables[INV_NAME[n]]
        assert len(fwd) == len(inv) == n // 2, f"degree {n}: bad table length"
        for i, (r, r_inv) in enumerate(zip(fwd, inv)):
            assert 0 < r < Q and 0 < r_inv < Q, f"degree {n}[{i}]: out of range"
            assert r * r_inv % Q == 1, f"degree {n}[{i}]: {r} * {r_inv} != 1 mod q"
    print(f"ok: inverse tables pair entrywise (degrees 2..512, q = {Q})")


def eval_points(tables):
    """Evaluation-point ordering of the size-n NTT, chained from the tables."""
    assert tables[FWD_NAME[2]] == [SQR1] and SQR1 * SQR1 % Q == Q - 1
    pts = {2: [SQR1, Q - SQR1]}
    for n in DEGREES:
        t = tables[FWD_NAME[n]]
        pts[n] = []
        for i, r in enumerate(t):
            assert r * r % Q == pts[n // 2][i], (
                f"degree {n}[{i}]: {r}^2 != point {pts[n // 2][i]}"
            )
            pts[n] += [r, Q - r]
    for n, p in pts.items():
        assert all(pow(x, n, Q) == Q - 1 for x in p), f"degree {n}: not roots of x^n + 1"
        assert len(set(p)) == n, f"degree {n}: evaluation points not distinct"
    print("ok: root chain consistent; all points are distinct 2n-th primitive roots")
    return pts


def ntt(f, tables):
    """Mirror of the Cairo split/merge NTT."""
    n = len(f)
    if n == 2:
        t = SQR1 * f[1]
        return [(f[0] + t) % Q, (f[0] - t) % Q]
    f0_ntt, f1_ntt = ntt(f[0::2], tables), ntt(f[1::2], tables)
    out = []
    for f0, f1, r in zip(f0_ntt, f1_ntt, tables[FWD_NAME[n]]):
        out += [(f0 + r * f1) % Q, (f0 - r * f1) % Q]
    return out


def intt(f_ntt, tables):
    """Mirror of the Cairo split/merge INTT."""
    n = len(f_ntt)
    if n == 2:
        sqr1_inv = pow(SQR1, -1, Q)
        return [
            I2 * (f_ntt[0] + f_ntt[1]) % Q,
            I2 * (f_ntt[0] - f_ntt[1]) * sqr1_inv % Q,
        ]
    f0, f1 = [], []
    for i, r_inv in enumerate(tables[INV_NAME[n]]):
        even, odd = f_ntt[2 * i], f_ntt[2 * i + 1]
        f0.append(I2 * (even + odd) % Q)
        f1.append(I2 * (even - odd) * r_inv % Q)
    f0, f1 = intt(f0, tables), intt(f1, tables)
    return [c for pair in zip(f0, f1) for c in pair]


def check_transform(tables, pts):
    rng = random.Random(12289)
    for n in DEGREES:
        for _ in range(3):
            f = [rng.randrange(Q) for _ in range(n)]
            got = ntt(f, tables)
            # Horner evaluation at each chained point: independent of split/merge.
            direct = [
                sum(c * pow(p, k, Q) for k, c in enumerate(f)) % Q for p in pts[n]
            ]
            assert got == direct, f"degree {n}: split/merge NTT != direct evaluation"
            assert intt(got, tables) == f, f"degree {n}: INTT(NTT(f)) != f"
    print("ok: split/merge NTT == direct evaluation and round-trips (random inputs)")


def check_against_falcon_py(tables, falcon_py_dir):
    sys.path.insert(0, str(falcon_py_dir))
    import ntt as fpy_ntt  # noqa: E402
    import ntt_constants as fpy_const  # noqa: E402

    for n in [2] + DEGREES:
        assert tables[FWD_NAME[n]] == fpy_const.roots_dict_Zq[n][0::2], (
            f"degree {n}: table != falcon.py roots_dict_Zq even entries"
        )
    rng = random.Random(831)
    for _ in range(5):
        f = [rng.randrange(Q) for _ in range(512)]
        assert ntt(f, tables) == fpy_ntt.ntt(f), "NTT output != falcon.py ntt()"
    kat = ntt(list(range(1, 513)), tables)
    assert kat == fpy_ntt.ntt(list(range(1, 513)))
    assert kat[:8] == [5279, 3373, 4474, 2755, 3765, 9923, 3810, 3849], (
        "KAT prefix != vector pinned in the Cairo test_ntt_512"
    )
    print("ok: tables and NTT outputs match tprest/falcon.py (interop convention)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--falcon-py",
        type=Path,
        help="path to a github.com/tprest/falcon.py clone for the cross-check",
    )
    args = parser.parse_args()

    tables = parse_tables(CAIRO_FILE)
    check_inverse_pairing(tables)
    pts = eval_points(tables)
    check_transform(tables, pts)
    if args.falcon_py:
        check_against_falcon_py(tables, args.falcon_py)
    else:
        print("skipped: falcon.py cross-check (pass --falcon-py PATH to enable)")
    print("all checks passed")


if __name__ == "__main__":
    main()
