# Hint vs direct verification

Falcon-512 verification here comes in two forms, **hint** and **direct**. They differ in
one thing only: how the verifier obtains the polynomial product `s1 * h`. Everything else
— the hash-to-point, the public key, the acceptance rule, the security level — is the
same. This note explains the distinction, what it affects, and what it does not. A short
glossary of the terms (NTT, the ring, hash-to-point, ...) is at the end.

## What both variants compute

A Falcon signature is accepted when a short vector exists that maps the public key to the
message. Concretely, given the message point `c` (from the hash-to-point), the signature's
short polynomial `s1`, and the public key polynomial `h`, the verifier forms

```
s0 = c - s1 * h        (in the ring Z_q[x]/(x^512 + 1))
```

and accepts iff the centered norm `||s0||^2 + ||s1||^2` is below the Falcon bound. The
only expensive part is `s1 * h`: a multiplication of two degree-511 polynomials modulo
`x^512 + 1`. Both variants need this product; they get it differently.

## The difference

**Hint.** The signer computes `s1 * h` off-chain and ships it inside the signature (29
extra packed felts, called `mul_hint`). On-chain the verifier does not recompute the
product; it *checks* the supplied one. It takes the forward NTT of `s1` and of `mul_hint`,
and verifies `NTT(s1) . h_ntt == NTT(mul_hint)` pointwise. Because the NTT is a bijection,
a `mul_hint` that passes this check is necessarily the true `s1 * h` — it cannot be
forged. So the on-chain work is **two forward NTTs** and a pointwise comparison.

**Direct.** No hint is supplied. The verifier computes `s1 * h` itself, on-chain, as
`INTT(NTT(s1) . h_ntt)` — **one forward NTT and one inverse NTT** (the public key is
already stored in the NTT domain, so `h` needs no transform). The signature is just the
minimal `s1 || salt` (31 felts), and nothing beyond a standard signature comes from the
signer.

The direct signature is exactly the first 31 felts of the hint signature (`s1 || salt`),
so the same signer produces both; the hint form only appends `mul_hint`.

## What it affects

| | Hint | Direct |
|---|---|---|
| Signature size | 60 felts (`s1 \|\| salt \|\| mul_hint`) | 31 felts (`s1 \|\| salt`) |
| Signer emits `s1 * h`? | yes (the hint) | no |
| On-chain transforms | 2 forward NTTs | 1 NTT + 1 INTT |
| Input trust surface | larger (an extra signer-supplied value, checked on-chain) | minimal (just `s1`) |
| On-chain cost | lower | higher (see below) |

**Cost.** Computing the product on-chain (direct) costs more than checking a supplied one
(hint). The premium is a fixed amount of transform work — about **+4.5M L2 gas and +45k
steps** — regardless of the hash-to-point. As a percentage it therefore depends on the
base: roughly **+17%** on the cheap BLAKE2s variant, but only **+7% gas / +10% steps** on
the SHAKE-256 variant, whose cost is dominated by Keccak. Exact per-variant figures are in
the [efficiency table](README.md#current-efficiency).

## What it does not affect

- **The hash-to-point.** Deriving `c` from `message_hash` and `salt` is a separate axis
  (BLAKE2s, SHAKE-256, or Poseidon). Hint and direct can each pair with any of them; the
  hint/direct choice never changes how `c` is computed.
- **The public key.** Both consume the same 29-felt NTT-domain `h`.
- **The acceptance rule and security.** The verification equation and the norm bound are
  identical; both check exactly the same mathematical relation, so the security is the
  same. Direct simply removes the signer-supplied value from the trust surface.
- **FIPS signer compatibility.** For the SHAKE-256 variants the sampler and hashing are
  unchanged either way. The hint form only adds `s1 * h` to the *encoding*; the direct
  form changes nothing at all, mirroring a bare FIPS signature most closely.

## Glossary

- **The ring `Z_q[x]/(x^512 + 1)`** — polynomials of degree below 512 whose coefficients
  are taken modulo `q = 12289`, with the wraparound rule `x^512 = -1`. Falcon's keys,
  signatures, and message points all live here.
- **Negacyclic** — the `x^512 = -1` wraparound (as opposed to `x^512 = +1`, "cyclic"). It
  is why a term that overflows degree 511 comes back negated.
- **NTT (Number-Theoretic Transform)** — the finite-field analogue of the FFT. It turns a
  polynomial into an evaluation form in which multiplication is cheap: `NTT(a) . NTT(b)`
  pointwise equals `NTT(a * b)`. **Forward NTT** goes to that domain; **inverse NTT
  (INTT)** comes back. Shared engine: [`crates/ntt`](../ntt).
- **`h_ntt`** — the public key polynomial `h` stored already in the NTT domain, so
  pointwise products with it need no transform.
- **hash-to-point** — maps `(message_hash, salt)` to the message point `c`, a polynomial
  in the ring, via an extendable-output hash with rejection sampling. The BLAKE2s /
  SHAKE-256 / Poseidon backends are three implementations of this step.
- **`s1`, `s0`** — the two short polynomials of a Falcon signature. `s1` is transmitted;
  `s0` is recomputed on-chain from the equation and never sent.
- **`mul_hint`** — the signer-supplied `s1 * h` product carried by the hint variants.
- **salt** — a 40-byte random value bound into the hash-to-point so the same message
  yields different points; carried as two felts.
- **centered norm** — the squared length of a signature's coefficients taken as signed
  values in `[-q/2, q/2]`. Acceptance requires it below the Falcon-512 bound.
- **felt / felt252** — Starknet's native field element. Coefficients are packed into felts
  for calldata and storage (512 coefficients into 29 felts here).
