#!/usr/bin/env python3
"""Model, verify, and emit the tables for the iterative lazy-reduction NTT engine
(`crates/ntt`).

The Cairo engine reformulates the recursive split/merge NTT (tprest/falcon.py
convention, tables verified by `scripts/verify_ntt_constants.py`) as: one
bit-reversal permutation, then merge-only levels bottom-up — with all butterfly
arithmetic done natively in felt252 and modular reduction DELAYED to at most two
u128 reduction passes per transform. This script is the engine's correctness
argument, kept executable:

  1. models the iterative forward/inverse transforms EXACTLY as the Cairo engine
     computes them (same operation order, same per-level offsets `off = bound*q`,
     same bits-based reduction schedule with threshold 126);
  2. proves them equal to the recursive reference for every size 4..512 on random,
     ramp, zero, delta, and worst-case all-(q-1) inputs, including the lazy
     unreduced-product INTT path used by the direct Falcon variant;
  3. asserts no intermediate value ever reaches 2^126 (so felt252 arithmetic never
     wraps and every reduction input fits u128);
  4. derives the bit-reversal permutation, the I2-scaled inverse root tables, and
     a fully unrolled Falcon-512 forward transform, then (with --emit) writes the
     formatter-clean generated Cairo sources.

Exits non-zero on any mismatch.
"""

import argparse
import random
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

Q = 12289
SQR1 = 1479  # square root of -1 mod q
I2 = 6145  # inverse of 2 mod q
STARK_PRIME = 2**251 + 17 * 2**192 + 1
DEGREES = [4, 8, 16, 32, 64, 128, 256, 512]
ALL_SIZES = [2] + DEGREES

# Mirrors of the Cairo engine's config constants.
QBITS = Q.bit_length()  # 14: reduced values are < q < 2^14
FWD_GROWTH_BITS = (Q + 1).bit_length()  # 14: per merge level, bound *= (q+1)
INV_GROWTH_BITS = (2 * Q).bit_length()  # 15: per split level, bound *= 2q
PRODUCT_BITS = 2 * QBITS  # 28: unreduced pointwise products are < q^2
THRESHOLD = 126  # felt252 wrap safety and u128 reduction-input bound

REPO = Path(__file__).resolve().parent.parent
ROOTS_LOCATIONS = [
    REPO / "crates/ntt/src/roots.cairo",
    REPO / "crates/falcon_512/src/ntt_constants.cairo",
]
SCALED_OUT = REPO / "crates/ntt/src/roots_scaled.cairo"
FELT_OUT = REPO / "crates/ntt/src/roots_felt.cairo"
BITREV_OUT = REPO / "crates/ntt/src/bitrev.cairo"
FAST_FALCON512_OUT = REPO / "crates/ntt/src/falcon512_fast.cairo"

FWD_NAME = {n: f"phi{2 * n}_roots_zq" for n in ALL_SIZES}
INV_NAME = {n: f"phi{2 * n}_roots_zq_inv" for n in ALL_SIZES}


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


# --- Recursive reference (identical to verify_ntt_constants.py / the old Cairo NTT) ---


def ntt_rec(f, tables):
    n = len(f)
    if n == 2:
        t = SQR1 * f[1]
        return [(f[0] + t) % Q, (f[0] - t) % Q]
    f0_ntt, f1_ntt = ntt_rec(f[0::2], tables), ntt_rec(f[1::2], tables)
    out = []
    for f0, f1, r in zip(f0_ntt, f1_ntt, tables[FWD_NAME[n]]):
        out += [(f0 + r * f1) % Q, (f0 - r * f1) % Q]
    return out


def intt_rec(f_ntt, tables):
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
    f0, f1 = intt_rec(f0, tables), intt_rec(f1, tables)
    return [c for pair in zip(f0, f1) for c in pair]


# --- Fully unrolled Falcon-512 forward transform ---


class ConcreteOps:
    """Integer operations for the generated circuit's unreduced arithmetic."""

    @staticmethod
    def mul_const(value, constant):
        return value * constant

    @staticmethod
    def add(left, right):
        return left + right

    @staticmethod
    def sub(left, right):
        return left - right


@dataclass(frozen=True)
class CairoValue:
    """A generated Cairo local together with its exact inclusive integer bounds."""

    name: str
    low: int
    high: int


class CairoOps:
    """Trace straight-line felt252 operations while proving their integer bounds."""

    def __init__(self):
        self.lines = []
        self.next_id = 0
        self.low = 0
        self.high = Q - 1

    def _record(self, expression, low, high):
        name = f"v{self.next_id}"
        self.next_id += 1
        self.lines.append(f"    let {name} = {expression};")
        self.low = min(self.low, low)
        self.high = max(self.high, high)
        return CairoValue(name, low, high)

    def mul_const(self, value, constant):
        return self._record(
            f"{value.name} * {constant}", value.low * constant, value.high * constant
        )

    def add(self, left, right):
        return self._record(
            f"{left.name} + {right.name}", left.low + right.low, left.high + right.high
        )

    def sub(self, left, right):
        return self._record(
            f"{left.name} - {right.name}", left.low - right.high, left.high - right.low
        )


def ntt_unrolled(f, tables, ops):
    """Recursive Falcon NTT whose operation graph is fully expanded at generation time.

    No modular reduction occurs inside the graph. A single reduction per output is
    sufficient because every operation is over the integers modulo q and the graph's
    exact bounds fit the felt252/u128 conversion used by the generated Cairo wrapper.
    """
    n = len(f)
    if n == 2:
        product = ops.mul_const(f[1], SQR1)
        return [ops.add(f[0], product), ops.sub(f[0], product)]

    even = ntt_unrolled(f[0::2], tables, ops)
    odd = ntt_unrolled(f[1::2], tables, ops)
    out = []
    for left, right, root in zip(even, odd, tables[FWD_NAME[n]]):
        product = ops.mul_const(right, root)
        out.append(ops.add(left, product))
        out.append(ops.sub(left, product))
    return out


def shift_for_bound(low):
    """Smallest non-negative multiple of q that offsets an inclusive lower bound."""
    if low >= 0:
        return 0
    return ((-low + Q - 1) // Q) * Q


# --- Iterative lazy-reduction models (exact mirrors of the Cairo engine) ---


def bitrev_perm(n):
    bits = n.bit_length() - 1
    return [int(format(i, f"0{bits}b")[::-1], 2) for i in range(n)]


def merge_roots_felts(tables, n):
    """merge_roots[level]: level ℓ merges into size 2^(ℓ+1)."""
    return [tables[FWD_NAME[size]] for size in ALL_SIZES if size <= n]


def scaled_inv_tables(tables):
    """tinv[i] = I2 * root_inv[i] mod q, per size (used by the split levels)."""
    scaled = {2: [I2 * pow(SQR1, -1, Q) % Q]}
    for n in DEGREES:
        scaled[n] = [I2 * r % Q for r in tables[INV_NAME[n]]]
    return scaled


class Stats:
    def __init__(self):
        self.max_value = 0
        self.reduce_passes = 0

    def see(self, values):
        self.max_value = max(self.max_value, max(values))


def ntt_iter_lazy(f, tables, stats=None):
    """The engine's `ntt_lazy`: the iterative forward transform WITHOUT its final
    reduction pass. Returns `(values, bits, bound)` exactly as the Cairo engine does."""
    n = len(f)
    stats = stats or Stats()
    perm = bitrev_perm(n)
    cur = [f[perm[i]] for i in range(n)]
    roots_by_level = merge_roots_felts(tables, n)
    bits, bound = QBITS, Q
    h, level = 1, 0
    while h != n:
        if bits + FWD_GROWTH_BITS > THRESHOLD:
            cur = [v % Q for v in cur]
            bits, bound = QBITS, Q
            stats.reduce_passes += 1
        roots = roots_by_level[level]
        off = bound * Q
        out = []
        for b in range(0, n, 2 * h):
            f0, f1 = cur[b : b + h], cur[b + h : b + 2 * h]
            for i in range(h):
                t = roots[i] * f1[i]
                out.append(f0[i] + t)
                out.append(f0[i] + off - t)
        cur = out
        stats.see(cur)
        assert all(v >= 0 for v in cur), "negative intermediate (offset too small)"
        bound *= Q + 1
        bits += FWD_GROWTH_BITS
        h, level = 2 * h, level + 1
    return cur, bits, bound


def ntt_iter(f, tables, stats=None):
    stats = stats or Stats()
    cur, _, _ = ntt_iter_lazy(f, tables, stats)
    stats.reduce_passes += 1
    return [v % Q for v in cur]


def intt_iter(f_ntt, tables, input_bits=QBITS, input_bound=None, stats=None):
    n = len(f_ntt)
    stats = stats or Stats()
    scaled = scaled_inv_tables(tables)
    sizes = [s for s in ALL_SIZES if s <= n]
    cur = list(f_ntt)
    bits = input_bits
    if input_bound is None:
        input_bound = Q**2 if input_bits == PRODUCT_BITS else Q
    bound = input_bound
    h, level = n // 2, len(sizes) - 1
    while True:
        if bits + INV_GROWTH_BITS > THRESHOLD:
            cur = [v % Q for v in cur]
            bits, bound = QBITS, Q
            stats.reduce_passes += 1
        tinv = scaled[sizes[level]]
        off = bound * Q
        out = []
        for b in range(0, n, 2 * h):
            tmp = []
            for i in range(h):
                x0, x1 = cur[b + 2 * i], cur[b + 2 * i + 1]
                out.append(I2 * (x0 + x1))
                tmp.append(tinv[i] * x0 + off - tinv[i] * x1)
            out.extend(tmp)
        cur = out
        stats.see(cur)
        assert all(v >= 0 for v in cur), "negative intermediate (offset too small)"
        bound *= 2 * Q
        bits += INV_GROWTH_BITS
        if h == 1:
            break
        h, level = h // 2, level - 1
    perm = bitrev_perm(n)
    stats.reduce_passes += 1
    return [cur[perm[i]] % Q for i in range(n)]


# --- Checks ---


def sample_inputs(n, rng):
    return [
        [0] * n,
        [Q - 1] * n,  # worst case for bound growth
        [1] + [0] * (n - 1),  # delta
        list(range(1, n + 1)),  # the KAT ramp pinned in the Cairo tests
        *([[rng.randrange(Q) for _ in range(n)] for _ in range(5)]),
    ]


def check_equivalence(tables):
    rng = random.Random(12289)
    stats = Stats()
    for n in DEGREES:
        for f in sample_inputs(n, rng):
            expect = ntt_rec(f, tables)
            got = ntt_iter(f, tables, stats)
            assert got == expect, f"n={n}: iterative NTT != recursive reference"
            back = intt_iter(expect, tables, stats=stats)
            assert back == f, f"n={n}: iterative INTT(NTT(f)) != f"
            assert intt_rec(expect, tables) == back, f"n={n}: INTT mismatch vs recursive"
    print(
        f"ok: iterative == recursive for sizes 4..512 "
        f"(max intermediate 2^{stats.max_value.bit_length()}, threshold 2^{THRESHOLD})"
    )
    assert stats.max_value < 2**THRESHOLD


def check_lazy_product_path(tables):
    """Direct-variant path: INTT over UNREDUCED pointwise products (< q^2)."""
    rng = random.Random(831)
    stats = Stats()
    for n in DEGREES:
        for _ in range(3):
            a = [rng.randrange(Q) for _ in range(n)]
            b = [rng.randrange(Q) for _ in range(n)]
            a_ntt, b_ntt = ntt_rec(a, tables), ntt_rec(b, tables)
            lazy_products = [x * y for x, y in zip(a_ntt, b_ntt)]  # NOT reduced
            reduced_products = [p % Q for p in lazy_products]
            expect = intt_rec(reduced_products, tables)
            got = intt_iter(lazy_products, tables, input_bits=PRODUCT_BITS, stats=stats)
            assert got == expect, f"n={n}: lazy-product INTT != reduced reference"
    print(
        f"ok: lazy-product INTT path (input < q^2) matches "
        f"(max intermediate 2^{stats.max_value.bit_length()})"
    )
    assert stats.max_value < 2**THRESHOLD


def check_lazy_forward(tables):
    """The engine's `ntt_lazy` contract: unreduced outputs match the reference mod q,
    respect the reported exact bound, and feed the direct-variant pipeline (products
    of a lazy transform against a reduced one, then INTT under the lazy bound)."""
    rng = random.Random(929)
    stats = Stats()
    for n in DEGREES:
        for f in ([Q - 1] * n, [rng.randrange(Q) for _ in range(n)]):
            expect = ntt_rec(f, tables)
            lazy, bits, bound = ntt_iter_lazy(f, tables, stats)
            assert [v % Q for v in lazy] == expect, f"n={n}: lazy fwd != reference mod q"
            assert all(v < bound for v in lazy), f"n={n}: lazy output >= reported bound"
            assert bound <= 2**bits <= 2**THRESHOLD, f"n={n}: lazy bits/bound inconsistent"

            g = [rng.randrange(Q) for _ in range(n)]
            g_ntt = ntt_rec(g, tables)
            products = [x * y for x, y in zip(lazy, g_ntt)]
            expect_fg = intt_rec([p % Q for p in products], tables)
            got = intt_iter(
                products, tables, input_bits=bits + QBITS, input_bound=bound * Q, stats=stats
            )
            assert got == expect_fg, f"n={n}: lazy-forward product pipeline mismatch"
    print(
        f"ok: lazy forward (no final pass) matches mod q, bounds hold, and the "
        f"product pipeline agrees (max intermediate 2^{stats.max_value.bit_length()})"
    )
    assert stats.max_value < 2**THRESHOLD


def check_negacyclic(tables):
    """x * x^511 = x^512 = -1 mod (x^512 + 1): full lazy pipeline check."""
    n = 512
    f = [0, 1] + [0] * (n - 2)
    g = [0] * (n - 1) + [1]
    prods = [x * y for x, y in zip(ntt_iter(f, tables), ntt_iter(g, tables))]
    res = intt_iter(prods, tables, input_bits=PRODUCT_BITS)
    assert res == [Q - 1] + [0] * (n - 1), "negacyclic wrap mismatch"
    print("ok: negacyclic convolution through the full lazy pipeline")


def check_schedule(tables):
    """The documented cost claim: at most 2 reduction passes per transform, and a
    single pass for the lazy forward."""
    f = [Q - 1] * 512
    s = Stats()
    ntt_iter(f, tables, s)
    assert s.reduce_passes == 2, f"fwd reduce passes = {s.reduce_passes}, expected 2"
    s = Stats()
    ntt_iter_lazy(f, tables, s)
    assert s.reduce_passes == 1, f"lazy fwd reduce passes = {s.reduce_passes}, expected 1"
    s = Stats()
    intt_iter([Q - 1] * 512, tables, stats=s)
    assert s.reduce_passes == 2, f"intt reduce passes = {s.reduce_passes}, expected 2"
    s = Stats()
    intt_iter([(Q - 1) ** 2] * 512, tables, input_bits=PRODUCT_BITS, stats=s)
    assert s.reduce_passes == 2, f"lazy intt reduce passes = {s.reduce_passes}"
    print(
        "ok: reduction schedule = 2 passes per 512-point transform "
        "(1 for the lazy forward)"
    )


def check_falcon512_unrolled(tables):
    """Prove the generated straight-line graph against the modular reference."""
    rng = random.Random(512)
    samples = sample_inputs(512, rng)
    for f in samples:
        raw = ntt_unrolled(f, tables, ConcreteOps())
        expect = ntt_rec(f, tables)
        assert [value % Q for value in raw] == expect, "unrolled NTT != reference"

    trace = CairoOps()
    inputs = [CairoValue(f"f{i}", 0, Q - 1) for i in range(512)]
    outputs = ntt_unrolled(inputs, tables, trace)
    shift = shift_for_bound(trace.low)
    assert shift % Q == 0
    assert min(value.low for value in outputs) + shift >= 0
    shifted_high = max(value.high for value in outputs) + shift
    assert shifted_high < 2**128, "generated output does not fit u128 after shift"
    assert max(abs(trace.low), trace.high) < STARK_PRIME, (
        "generated felt arithmetic exceeds the Stark field"
    )
    print(
        "ok: fully unrolled Falcon-512 NTT matches the reference "
        f"({trace.next_id} operations, shifted outputs < 2^{shifted_high.bit_length()})"
    )


# --- Emission ---

HEADER = """\
// GENERATED by scripts/gen_ntt_tables.py — do not edit by hand.
// {what}
// Regenerate with: python3 scripts/gen_ntt_tables.py --emit
"""


def fmt_table(name, values, ty="u16"):
    body = ", ".join(str(v) for v in values)
    return f"const {name}: [{ty}; {len(values)}] = [{body}];\n"


def emit_dispatch(out, fn_name, doc, names):
    out.append(f"\n{doc}pub fn {fn_name}(degree: u32) -> Span<felt252> {{\n")
    branches = []
    for n in ALL_SIZES:
        branches.append(f"    if degree == {n} {{\n        {names[n]}.span()\n    }}")
    out.append(
        " else ".join(branches)
        + " else {\n        panic!(\"no root table for degree\")\n    }\n}\n"
    )


def emit_scaled(tables):
    scaled = scaled_inv_tables(tables)
    out = [
        HEADER.format(
            what=(
                "Inverse merge-root tables prescaled by I2 = 2^-1 mod q\n"
                "// (tinv[i] = I2 * root_inv[i] mod q), derived from roots.cairo; the\n"
                "// split levels of the INTT consume them as single felt252 multipliers."
            )
        ),
        "\n//! I2-scaled inverse NTT root tables (generated).\n\n",
    ]
    names = {}
    for n in ALL_SIZES:
        names[n] = f"phi{2 * n}_roots_zq_inv_scaled"
        out.append(fmt_table(names[n], scaled[n], ty="felt252"))
    emit_dispatch(
        out,
        "get_scaled_inv_roots",
        "/// I2-prescaled inverse roots for the split level of the given degree\n"
        "/// (the output size of the merge it inverts).\n",
        names,
    )
    SCALED_OUT.write_text("".join(out))
    print(f"wrote {SCALED_OUT.relative_to(REPO)}")


def emit_felt_roots(tables):
    out = [
        HEADER.format(
            what=(
                "Forward merge-root tables as felt252 constants, value-identical to the\n"
                "// u16 tables in roots.cairo; the engine multiplies roots into felt252\n"
                "// butterflies, so the constants are stored ready to consume."
            )
        ),
        "\n//! Forward NTT root tables as felts (generated).\n\n",
    ]
    names = {}
    for n in ALL_SIZES:
        names[n] = f"phi{2 * n}_roots_zq_felt"
        out.append(fmt_table(names[n], tables[FWD_NAME[n]], ty="felt252"))
    emit_dispatch(
        out,
        "get_even_roots_felt",
        "/// Forward merge roots for the given degree, as felts (the values of\n"
        "/// `roots::get_even_roots`).\n",
        names,
    )
    FELT_OUT.write_text("".join(out))
    print(f"wrote {FELT_OUT.relative_to(REPO)}")


def emit_bitrev():
    perm = bitrev_perm(512)
    out = [
        HEADER.format(
            what=(
                "Bit-reversal permutation for n = 512 (self-inverse). The iterative\n"
                "// engine permutes inputs into recursion-leaf order before its merge\n"
                "// levels, and INTT outputs back to natural order."
            )
        ),
        "\n//! Bit-reversal permutation table (generated).\n\n",
        fmt_table("BITREV_512", perm).replace("const", "pub(crate) const", 1),
        "\n/// The 512-entry bit-reversal permutation as a span.\n",
        "pub fn bitrev_512() -> Span<u16> {\n    BITREV_512.span()\n}\n",
    ]
    BITREV_OUT.write_text("".join(out))
    print(f"wrote {BITREV_OUT.relative_to(REPO)}")


def wrapped(items, indent="    ", width=100):
    """Format a comma-separated generated list without depending on a Cairo formatter."""
    lines = []
    current = indent
    for item in items:
        token = f"{item},"
        if len(current) + len(token) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent + token + " "
        else:
            current += token + " "
    if current.strip():
        lines.append(current.rstrip())
    return "\n".join(lines)


def emit_falcon512_fast(tables):
    trace = CairoOps()
    inputs = [CairoValue(f"f{i}", 0, Q - 1) for i in range(512)]
    outputs = ntt_unrolled(inputs, tables, trace)
    shift = shift_for_bound(trace.low)
    shifted_high = max(value.high for value in outputs) + shift
    assert min(value.low for value in outputs) + shift >= 0
    assert shifted_high < 2**128

    input_params = [f"f{i}: felt252" for i in range(512)]
    input_names = [f"f{i}" for i in range(512)]
    reduced_names = [f"r{i}" for i in range(512)]
    return_type = "(" + ", ".join("Falcon512Zq" for _ in outputs) + ")"

    out = [
        HEADER.format(
            what=(
                "Fully unrolled Falcon-512 forward NTT for n = 512 and q = 12289.\n"
                "// The operation graph and its bounds are derived from roots.cairo; each\n"
                "// output is reduced once after the straight-line felt252 arithmetic."
            )
        ),
        "\n//! Generated Falcon-512 forward NTT.\n//!\n",
        "//! Inputs are 512 coefficients in `[0, 12289)`. The unchecked public entry points\n",
        "//! rely on callers to enforce that precondition; the fixed operation graph computes\n",
        "//! the Falcon evaluation order and returns 512 reduced coefficients.\n\n",
        "use corelib_imports::bounded_int::{\n",
        "    BoundedInt, DivRemHelper, UnitInt, bounded_int_div_rem, upcast,\n",
        "};\n",
        "use corelib_imports::integer::{U128sFromFelt252Result, u128s_from_felt252};\n\n",
        "type Falcon512Zq = BoundedInt<0, 12288>;\n",
        "type Falcon512Q = UnitInt<12289>;\n",
        "type U128AsBounded = BoundedInt<0, 340282366920938463463374607431768211455>;\n\n",
        "const FALCON512_Q_NZ: NonZero<Falcon512Q> = 12289;\n",
        f"const SHIFT: felt252 = {shift};\n\n",
        "impl Falcon512FastDivRemImpl of DivRemHelper<U128AsBounded, Falcon512Q> {\n",
        "    type DivT = BoundedInt<0, 27689996494502275487295516920153650>;\n",
        "    type RemT = Falcon512Zq;\n",
        "}\n\n",
        "#[inline(always)]\n",
        "fn felt252_as_u128(value: felt252) -> u128 {\n",
        "    // Exact generated bounds put canonical shifted outputs below 2^128.\n",
        "    match u128s_from_felt252(value) {\n",
        "        U128sFromFelt252Result::Narrow(low) => low,\n",
        "        U128sFromFelt252Result::Wide((_, low)) => low,\n",
        "    }\n",
        "}\n\n",
        "#[inline(always)]\n",
        "fn ntt_falcon512_fast_inner(\n",
        wrapped(input_params, indent="    "),
        f"\n) -> {return_type} {{\n",
        "\n".join(trace.lines),
        "\n",
    ]

    for output, reduced in zip(outputs, reduced_names):
        out.extend(
            [
                f"    let {reduced}_bounded: U128AsBounded = ",
                f"upcast(felt252_as_u128({output.name} + SHIFT));\n",
                f"    let (_, {reduced}) = ",
                f"bounded_int_div_rem({reduced}_bounded, FALCON512_Q_NZ);\n",
            ]
        )
    out.extend(["    (\n", wrapped(reduced_names, indent="        "), "\n    )\n}\n\n"])

    out.extend(
        [
            "/// Compute the Falcon-512 forward NTT for 512 reduced coefficients without\n",
            "/// validating each coefficient.\n",
            "///\n",
            "/// Inputs must be in `[0, 12289)`; violating that precondition may return an\n",
            "/// invalid transform. Outputs are in the Falcon/falcon.py evaluation order and\n",
            "/// reduced to the same range.\n",
            "pub fn ntt_falcon512_fast_unchecked(mut f: Span<felt252>) -> Array<felt252> {\n",
            "    assert(f.len() == 512, 'fast NTT: bad length');\n",
            "    let boxed = f.multi_pop_front::<512>().unwrap();\n",
            "    let [\n",
            wrapped(input_names, indent="        "),
            "\n    ] = boxed.unbox();\n",
            "    let (\n",
            wrapped(reduced_names, indent="        "),
            "\n    ) = ntt_falcon512_fast_inner(\n",
            wrapped(input_names, indent="        "),
            "\n    );\n",
            "    array![\n",
            wrapped([f"upcast({name})" for name in reduced_names], indent="        "),
            "\n    ]\n",
            "}\n\n",
            "/// Compute the Falcon-512 forward NTT from canonical `u16` coefficients without\n",
            "/// validating each coefficient.\n",
            "///\n",
            "/// Inputs must be in `[0, 12289)`; violating that precondition may return an\n",
            "/// invalid transform. Outputs are in the Falcon/falcon.py evaluation order and\n",
            "/// reduced to the same range.\n",
            "pub fn ntt_falcon512_fast_u16_unchecked(mut f: Span<u16>) -> Array<u16> {\n",
            "    assert(f.len() == 512, 'fast NTT: bad length');\n",
            "    let boxed = f.multi_pop_front::<512>().unwrap();\n",
            "    let [\n",
            wrapped(input_names, indent="        "),
            "\n    ] = boxed.unbox();\n",
            "    let (\n",
            wrapped(reduced_names, indent="        "),
            "\n    ) = ntt_falcon512_fast_inner(\n",
            wrapped([f"{name}.into()" for name in input_names], indent="        "),
            "\n    );\n",
            "    array![\n",
            wrapped([f"upcast({name})" for name in reduced_names], indent="        "),
            "\n    ]\n",
            "}\n",
        ]
    )

    FAST_FALCON512_OUT.write_text("".join(out))
    print(f"wrote {FAST_FALCON512_OUT.relative_to(REPO)}")


def format_generated():
    """Apply the repository's pinned Cairo formatter to every emitted source."""
    for path in (SCALED_OUT, FELT_OUT, BITREV_OUT, FAST_FALCON512_OUT):
        subprocess.run(["scarb", "fmt", str(path)], cwd=REPO, check=True)
    print("formatted generated Cairo sources")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--emit", action="store_true", help="write the generated Cairo table files"
    )
    args = parser.parse_args()

    roots_path = next((p for p in ROOTS_LOCATIONS if p.exists()), None)
    if roots_path is None:
        sys.exit("root tables not found (crates/ntt or crates/falcon_512)")
    tables = parse_tables(roots_path)
    print(f"tables: {roots_path.relative_to(REPO)}")

    check_equivalence(tables)
    check_lazy_product_path(tables)
    check_lazy_forward(tables)
    check_negacyclic(tables)
    check_schedule(tables)
    check_falcon512_unrolled(tables)

    if args.emit:
        emit_scaled(tables)
        emit_felt_roots(tables)
        emit_bitrev()
        emit_falcon512_fast(tables)
        format_generated()
    print("all checks passed")


if __name__ == "__main__":
    main()
