# Changelog (`0l0`)

## Unreleased — project branding

- Display name is now `0l0` (README, docs, papers, copyright headers).
  Crate identifiers stay `sq-pq`/`sq_pq`: Cargo forbids package names
  starting with a digit, so a literal rename is impossible. No code,
  wire-format, or behavior change (full suite re-verified green).

## 0.3.0 — speed and size (S1+S2)

- Speed: NTT-domain mat-vec with per-call hoisting (`twisted_ntt_matrix`
  + `commit_precomputed`), fast `check_relation`, transcript hoisting —
  prover p50 `467→188 µs` (2.5×), verifier p50 `172→75 µs` (2.3×), proof
  bytes unchanged through S1 (differential stayed byte-identical).
- Size: 17-bit packed responses (v2 cutover, `6497 → 4577 B`, −30%),
  single-check canonicality, exhaustive 131072-word decoder sweep,
  `PROOF_VERSION 1→2` (v1 no longer verifies — breaking change).
- Python codec mirrored, differential re-verified byte-identical.

## 0.2.1 — variance finding + timing discipline (2026-09-30)

- REMOVED the `v = ⟨r,c⋆w⟩` wire value: variance analysis showed it
  encodes `‖cw‖₂` (sole statistical leak); pack slots zeroed, differential
  re-verified byte-identical. Responses now exactly uniform conditional on
  acceptance (χ² exhibit).
- Timing: constant-scan `response_ok`, branchless `centered`, Welch harness
  (`tests/timing.rs`), `docs/ct-audit.md` with 20-finding self-audit log.
- O1 closed by analysis (extractor verifies directly; no tail bound
  needed); wire-proof pack docs corrected throughout.

- Packing exact equality closed via knowledge-soundness extraction
  (`docs/extraction.md`, tiny-model exhibit 488/488); PARTIAL retired.
- Second-commitment design evaluated and rejected in writing (kernel
  ambiguity needs extraction either way).
- Independent Python model, byte-identical proofs (`tools/model.py`,
  `tests/model_diff.rs`).
- Exact Rényi/hiding numbers (`tools/renyi.py`) and Core-SVP margin memo
  (`tools/svp_estimate.py`, `docs/lattice-margin.md`); hiding MARGINAL.
- Whitepaper with Theorems 1–3 (`docs/whitepaper.md`).
- Timing discipline: constant-scan `response_ok`, branchless `centered`,
  Welch harness (`tests/timing.rs`), `docs/ct-audit.md`.
- Full benches with distributions; self-audit log with 20 findings;
  `cargo-fuzz` target (18 M+ runs clean); full Miri lib run green.
- Proof wire unchanged: `6497 B`, version 1.

## 0.1.0 — Production prototype scaffold

- Frozen relation `R*`, ring NTT, BLAKE3 core, Ajtai commitment,
  Lyubashevsky prover/verifier, red-team suites, publish-all docs.
