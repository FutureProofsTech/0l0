# Red-Team Log — brutal campaign (2026-09-30, measured, no editing of failures)

Environment: x86_64, rustc 1.97.1, `0l0` v0.3.0, dev profile unless noted.
Every entry below ran; counts are exact assertions in `tests/brutal.rs`
(plus cited suites), not estimates.

## B-series (new, `tests/brutal.rs`, 14 tests)

| ID | Vector | Method | Trials | Result |
|---|---|---|---|---|
| B1 | Single-bitflip forgery | all 4577 bytes × all 8 bits flipped, one at a time | 36,616 | **36,616/36,616 reject** |
| B2 | Two-bit forgery | 5000 random distinct position pairs, 1 bit each | 5,000 | **5,000/5,000 reject** |
| B3 | Round confusion | swap round-0 ↔ round-1 body blocks | 1 | reject (round index bound) |
| B4 | Cross-proof splice | `t1_0` transplant between two proofs (same `y`), both directions | 2 | reject both |
| B5 | Direct grinding | fully random 4577 B wire (version fixed; half with zeroed reserved) | 20,000 | **0/20,000 accepts** |
| B6 | Exhaustion census | 200 distinct salts, honest proving | 200 | **0 exhausted** (bound ≤ 2) |
| B7 | Sparsity classes | zero witness vs dense witness, 40 salts each | 80 | **0 + 0 exhausted** |
| B8 | Mask entropy | `z`-region byte distance across two salts | 1 | **1084/1088 bytes differ** |
| B9 | Decode edges | `t1` coeff `= Q`; pack scalar `= 0xFFFFFFFF` | 2 | both `MalformedEncoding` |
| B10 | Framing | lengths 0 / 4576 / 4577 / 4578 / 6497 | 5 | only exact length parses |
| B11 | API limits | 32769 B hash; 2049 B XOF out; 65 B label; 2049 B absorb; 0x00/0xFF matrix seeds | 6 | all fail closed / derive fine |
| B12 | (in B11 file section: seed edges) | — | — | deterministic + reduced + distinct |
| B13 | Transcript framing | `("ab","c")` vs `("a","bc")`; tag separation | 2 | diverge |
| B14 | Zero witness | `(w=0,y=0,t=0)` proves ×2 salts, verifies, diversifies | 2 | accept + diversify |

## Prior suites (re-verified this campaign)

- 65-pos sampled sweep (`prove_verify`): reject (kept; B1 supersedes with
  36,616 exhaustive — notably, the old sweep MISSED position 4229, a
  `v`-slot flip that accepted until audit finding F24 closed it).
- Wrong-`y`/`t`, tamper ×2, prover refusal, version/truncation, norm
  edges, grinding floor `C(64,16)·2^16 ≥ 2^64`, salt determinism: all green.
- Python adversarial agreement: 13/13 mutants rejected identically by both
  implementations (`tools/diff_vectors.py`).
- In-tree fuzzer: 2000-case mutation sweep + random arrays + transcript
  fuzz, green. `cargo-fuzz` run below.

## F24 malleability (found BY this campaign, fixed, exhibited)

Exhaustive B1 found flips at wire 4229 (`v0` slot) that verified: the
zeroed `v` slots were unauthenticated (verifier never read them).
  Impact: malleability only (same statement, no forgery, nothing learned).
  Fix: verifier enforces `v`-slots zero (`MalformedEncoding`); every wire
  byte is now functional+bound or enforced-zero. Python model mirrors the
  check. B1 re-run post-fix: 36,616/36,616 reject.

## Deliberately not executed (with reason, not silently dropped)

- Second-preimage on `t = A·w` / collisions on BLAKE3: infeasible by
  hardness assumption; covered analytically (`docs/lattice-margin.md`,
  KATs), not by trials.
- Fault injection / power / EM: no lab on this PC (threat model R3).
- Network adversary / replay across sessions: NIZK proofs are replayable
  by design; replay protection is the integrator's job (documented).
- `v1` resurrect-attacks: version byte enforced; legacy rejection tested.

## Tool runs (this campaign)

- `cargo-fuzz verify_parse`: see results (background run at log time).
- Miri full lib: see results (background run at log time).
- `cargo test`: 75/75 green (35 lib + 14 brutal + 3 + 3 + 1 + 2 + 5 + 8 + 3 + 1).
