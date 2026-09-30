# Constant-Time Audit (Q8 — per-site inventory, measured)

Scope: secret material is `w`, `r`, `z`, `c⋆w`, masks, salts-as-entropy.
Public material is `A`, `y`, `t`, proofs under verification, XOF streams
from public seeds. Verdicts: SAFE (fixed bounds, no value branches),
FIXED (changed in this push with test), ACCEPTED (residual, quantified).

## Prover-side secrets

| # | Site | Verdict | Reason |
|---|---|---|---|
| 1 | `field`-style `Z_q` add/mul (`ring::add_mod/mul_mod_u32`) | SAFE | wrapping arithmetic, no branches |
| 2 | `pow_mod`/`inv_mod` square-and-multiply | SAFE | mask-selected accumulate, fixed 32 steps |
| 3 | `poly_add/mul_naive/mul_nwc`, NTT butterflies | SAFE | fixed bounds; measured Welch `t = 0.64` (null) |
| 4 | `centered()` | FIXED | was `if c <= half` branch → now wrapping-sub mask arithmetic, `const fn`; behavior identical (full test suite green) |
| 5 | `response_ok()` | FIXED | was early-return (leaked first-bad position) → constant-scan flag accumulation; measured first-vs-last-bad Welch `t = 0.76` (pre-fix shape would be in the hundreds) |
| 6 | `check_relation` early returns | ACCEPTED | failure position leaks to a timing observer of the *prover*, who already knows `w`. Guidance: never call it on secrets in timing-sensitive contexts; `prove()` gates first. No remote oracle (caller-local). |
| 7 | `prove_round` attempt loop (≤8) | ACCEPTED | attempt count depends on secret-derived `z`; measured prove-latency spread min 154 / p50 204 / max 699 µs (dev, post-S1). Fixed-iteration (always 8) would 8× prover cost — deferred with these numbers. Salt rotation keeps trials independent. |
| 8 | `sample_mask` rejection `continue` | SAFE | over public XOF stream; acceptance independent of secrets |
| 9 | `expand_challenge` duplicate-skip | SAFE | over public XOF stream |
| 10 | `inner_prod` accumulation | SAFE | straight-line, `i128` exact |
| 11 | Transcript/hash absorbs of `t1`/`u` (mask-derived) | SAFE | fixed lengths ⇒ data-independent timing |

## Verifier side

All verifier inputs (proof bytes, `y`, `t`, `A`) are public by construction;
early returns on malformed/invalid inputs leak nothing secret. No action.

## Residual channels (accepted, quantified)

- R1: prover attempt count → ≤ ~10× latency spread (measured above).
- R2: `check_relation` failure position (see #6).
- R3: LLVM codegen of mask arithmetic + microarch (cache/power/EM):
  out of scope at prototype bar (threat model), no lab on this PC.

## Harness

`tests/timing.rs`: Welch t-tests (`nwc zero-vs-max`, `response
first-vs-last-bad`, threshold `|t| < 10`) + prove-latency distribution
report. Run: `cargo test --test timing -- --nocapture`.
