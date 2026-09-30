# Roadmap — `0l0`

All dates are release checkpoints; every item links its evidence file.
Status as of v0.3.0 (2026-09-30). License: GPLv3 (`LICENSE`).

## Shipped

### v0.1.0 — Production prototype scaffold
- Frozen relation `R*` over `R_q = Z_q[X]/(X^64+1)` (`docs/spec.md`).
- Ring NTT from scratch, BLAKE3 core (11/11 official KATs), Ajtai
  commitment, Lyubashevsky prover/verifier, red-team suites.
- Publish-all docs; honest PARTIAL label on packing sufficiency.

### v0.2.0 — MAX-Q push
- Packing closed via knowledge-soundness extraction (`docs/extraction.md`,
  tiny-model exhibit 488/488); PARTIAL retired.
- Independent Python model, byte-identical proofs (`tools/model.py`).
- Exact Rényi/hiding numbers, Core-SVP margin memo (MARGINAL verdict).
- Whitepaper Theorems 1–3; timing discipline + harness; self-audit log
  (20 findings); `cargo-fuzz` target; full Miri lib run green.

### v0.3.0 — Speed and size (current)
- NTT-domain mat-vec + per-call hoisting: prover p50 `467→188 µs` (2.5×),
  verifier p50 `172→75 µs` (2.3×), output bytes unchanged (differential
  stayed byte-identical through the refactor).
- 17-bit packed responses, v2 cutover: `6497 → 4577 B` (−30%), single-check
  canonicality, exhaustive 131072-word decoder sweep, `PROOF_VERSION 2`
  (v1 no longer verifies — breaking change).
- Real `v`-slot malleability found by exhaustive sweep (F24) and closed by
  canonical-zero enforcement.

## Planned

### v0.4.0 — Hiding upgrade (next)
- Gaussian sampling with Rényi analysis to replace the marginal uniform-mask
  computational leg (`2^38–2^42`); re-measure acceptance `M`, re-run the
  full matrix (tests, differential, bench, estimator).
- BKZ simulation depth beyond closed-form δ(β) (G6K-style tour modeling).
- Closed-form forking-reduction constants (O2) if the estimator pass demands it.
- `zero-sq` stays archived; no changes planned there.

### v1.0.0 — Release candidate (requires external input)
- External security audit by an independent firm (cannot be done in-tree).
- NIST-level parameter blessing via a full lattice-estimator pass.
- Lab-grade side-channel evaluation (EM/power).
- MSRV policy beyond stable-only, platform support matrix, CVE process.
- Criteria to leave this phase: audit findings closed, estimator sign-off.

### Explicitly out of scope (never planned)
General circuits/VM, recursion, proof aggregation, sub-900 B proofs,
post-quantum reduction proofs from new assumptions, consensus deployment
guidance. Rationale for each is in `docs/negative-results.md`.
