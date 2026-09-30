# Self-Audit Log (Q10 — two passes, all findings recorded)

## Pass 1: spec ↔ code ↔ test mapping

| Spec claim (`docs/spec.md`, `whitepaper.md`) | Code | Exhibiting test |
|---|---|---|
| `R*` linear + norms + packing | `prover::check_relation` | `zero_witness…`, `norm_violation_fails` |
| NTT order / roundtrip / linearity | `ring::{ntt_core,ntt_forward,…}` | `roots_have_exact_order`, `ntt_roundtrip`, `ntt_linearity` |
| NWC == naive bitwise | `ring::poly_mul_nwc` | `nwc_matches_naive_differential` (64 + max-coeff) |
| Challenge-difference invertibility | `ring::nwc_has_zero` | `challenge_differences_invertible` (200 pairs) |
| BLAKE3 spec-exact | `hash::*` | `kat_hash` 11/11 official vectors |
| Matrix determinism / linearity | `commit::{derive_matrix,commit}` | commit unit tests |
| Gadget roundtrip (31-bit) | `commit::{decomp,compose}_coeff` | `gadget_roundtrip` |
| Mask bounds / acceptance band / shift | `sample_mask`, `response_ok`, `expand_challenge` | prover unit tests (band 14..34, shift ≤ 16) |
| Joint TV pin | frozen consts | `hiding_joint_tv_bound` (`131072 ≤ 131073`) |
| Linear equations + bounds + binding | `verifier::{verify,verify_round}` | `prove_verify` 8 (incl. 65-pos bitflip) |
| Packing via extraction | `docs/extraction.md` + harness | `tiny_extract` 488/488, biased-`u` demo |
| Salt discipline / determinism | `prove` salt param | `p7_audit`, `zero_salt_determinism_warning` |
| No-panic on adversarial bytes | all parsers | `fuzz_in_tree` + `cargo-fuzz` 14.9 M runs on v0.3.0 (+34 M prior) |
| Timing independence | `response_ok`, field ops | `tests/timing.rs` Welch tests |
| Byte-identical second implementation | `tools/model.py` | `tests/model_diff.rs` |
| Grinding floor | challenge expansion | `grinding_space_floor` (`C(64,16)` exact) |

## Pass 2: fresh-eyes findings (all dispositions)

- F1 `sample_mask` try_from().expect in library: reviewed-unreachable
  (`Q + centered < 2^31` always); private fn; ACCEPTED with note.
- F2 `expand_challenge` zero-poly fallback on XOF error: unreachable
  (128 B ≤ cap) and fail-closed (verifier would reject); logged.
- F3 `prove`/`prove_with_u_bias` assembly duplication → FIXED via shared
  `store_round`/`finish_proof` helpers (this push).
- F4 round index `as u8` truncation if `TAU ≥ 256` → FIXED via compile
  assert `TAU < 256` (this push).
- F5 small `as u8` casts (indices < 8/64): bounded, crate-allowed; logged.
- F6 salt rotation discipline: caller duty, tested; logged.
- F7 `uvs[2*j]` indexing: bounded by TAU loop + layout asserts; logged.
- F8 magic `0x77` + dead `TAG_FINAL` → FIXED (`TAG_WITNESS`, tag removed).
- F9 silent `let _ = xof_into` → FIXED (loud expect + Panics doc).
- F10 body-slice assembly: covered by layout asserts + roundtrips; logged.
- F11 `response_ok` early exit (timing oracle) → FIXED (constant scan,
  Welch `t = 0.76`).
- F12 `centered()` comparison branch → FIXED (wrapping-sub mask, const).
- F13 `check_relation` early returns on secrets → ACCEPTED residual with
  caller guidance (`docs/ct-audit.md` R2).
- F14 attempt-count latency channel → ACCEPTED residual, quantified
  (min 154 / p50 204 / max 699 µs dev post-S1; `docs/ct-audit.md` R1).
- F15 fuzz slice bug + no-op wipe semantics → FIXED + explicitly asserted.
- F16 bitflip threshold → reworked to exact noop accounting.
- F17 estimator inverted feasibility condition → FIXED (margin memo).
- F18 cyclic-vs-negacyclic test bug → FIXED (`nwc_has_zero` + §6 lesson).
- F19 false `Q` decomposition in docs+comment → FIXED (`2^30+2^13+1`).
- F20: matrix shortfall determinism landmine → FIXED (counter retries).
- F21: packing scalar `v = ⟨r,c⋆w⟩` VARIANCE ENCODES `‖cw‖₂` (`w = 0`
  forces `v ≡ 0`) — the sole statistical leak, found by systematic
  variance review → FIXED by REMOVING `v` from the wire (slots zeroed;
  byte-identical differential re-verified). Responses now exactly
  uniform conditional on acceptance (χ²-exhibited); computational leg
  unchanged (marginal).
- F22: Python model hardcoded params-version `1` in its transcript block
  → differential caught it (Rust v2 proofs rejected by model). FIXED by a
  shared `PROOF_VERSION` const in the model; lesson: constants that must
  agree across implementations get a single definition per side plus a
  differential that covers them (it did).
- F23 (S1/S2 review): `commit_fast` doc pointed at removed internals;
  duplicate `decode_u32` from a doc edit; `M_COLS`-vs-`N_ROWS` typo in
  deleted code; stale `as u8` in tests — all caught by
  `deny(warnings)` + `cargo doc` before any test ran. No finding survives.

## Sign-off (prototype bar)

Second implementation (Python, byte-identical) + exhaustive tiny model +
fuzz runs + full Miri lib runs + this log constitute the in-tree audit
substitute. No external firm engaged (labeled, not hidden). Open items:
O1 closed by analysis, O2 closed-form constants out of scope
(`docs/extraction.md` §5).
