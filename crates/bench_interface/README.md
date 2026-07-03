# Benchmark interface

**Component:** the common verifier interface and the validation-cap constants.
**Status:** no measurable code (trait and constants only).

Defines `PqSignatureVerifier` — the one surface every scheme implements so the harness
can swap and measure them identically:

```cairo
fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool;
```

It also carries the Starknet validation limits every verifier is judged against
(1,000,000 Cairo steps, 100,000,000 L2 gas) and the per-felt calldata cost constant.

## Current efficiency

Nothing to measure: the crate contains no executable logic, so it has no ratchet entries.
