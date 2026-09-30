# `0l0` Results (publish-all)

## Pre-registration

- H1 completeness: honest ternary `w` verifies (lands P6; `check_relation`
  ground truth green since P1).
- H2 soundness: forgery / norm smuggling / grinding / bitflips rejected.
- H3 ZK: responses statistically hide `w` (conditional uniformity +
  variance review of all wire values).
- H4 perf/size: `4577 B` fixed (v2 cutover); prover/verifier budgets from bench below.

## Current (P2–P9 built, 2026-09-30)

- `cargo test`: 75/75 green (dev) and 75/75 green (`--release`:
  debug asserts off, overflow wraps — same verdicts, incl. exhaustive
  packer sweep and 36,616-bitflip sweep) —
  lib 35 (params, `Z_q`/negacyclic, NTT order/roundtrip/linearity,
  NWC invertibility + 200-pair challenge-difference measurement,
  64-case NWC-vs-naive differential incl. max-coeff overflow catchers,
  matrix determinism/linearity, fast-vs-naive commitment differential,
  gadget roundtrip incl. the 31-bit fix, challenge weight ×1000 +
  euclidean edge,
  relation ground truth, proof container + framing entry, v1-cutover rejection,
  packer edges + 131072-word exhaustive canonicality,
  mask bounds, acceptance band,
  shift bound, joint-TV pin, χ² conditional-uniformity exhibit,
  biased-packing gap demo),
  `brutal` 14 (exhaustive 36,616-bitflip sweep, 5k pairs, round swap,
  cross-splice, 20k grinding game at 0 accepts, 200-salt census,
  sparsity classes, mask diversity, decode edges, framing, limits,
  seed edges, transcript framing, zero witness),
  `kat_hash` 3 (11/11 official BLAKE3 vectors, XOF separation, bitflip),
  `fuzz_in_tree` 3 (2000-case mutation sweep, random arrays, transcript),
  `model_diff` 1 (byte-identical Python differential),
  `tiny_extract` 1 (488/488 extraction, 0/2400 direct grinds),
  `p7_audit` 2 (60-salt success rate, salt discipline),
  `p8_redteam` 5 (bound edges, norm-smuggle refusal, grinding floor,
  version/reserved, salt determinism),
  `prove_verify` 8 (roundtrips ×2 salts, prover refusal, wrong-`y`/`t`,
  tamper ×2, 65-position bitflip sweep),
  `timing` 3 (NWC value-independence, scan position-independence,
  prove-latency distribution).
- `cargo audit`: exit 0, 0 vulnerabilities (1 crate — zero dependencies).
- Miri full lib suite: 35/35 green on final code, plus 33/33 (1789 s)
  and 29/29 (1401 s) on earlier snapshots. No UB in the 100% safe
  codebase under Miri's checks (expected —
  `forbid(unsafe_code)` — exhibited, not assumed).
- Miri incident note (published as found): an earlier v0.3.0 attempt
  appeared hung on `z_pack_exhaustive_words` (68 min CPU, no new output).
  Diagnosis via per-thread stats: single worker at 100% CPU, flat RSS,
  prior tests green — progressing, not hung: the binary predated the
  `cfg(miri)` gate and was interpreting all 131072 full decodes (~1000×
  slower than the 0.12 s native run). Killed after positive diagnosis;
  policy recorded: exhaustive sweeps get Miri-sampled paths with
  exhaustive boundaries; full sweeps stay in normal CI.
- `cargo-fuzz` `verify_parse`: 14.9 M runs on current code, 0 crashes
  (cumulative 49 M+ across runs, 1 harness-side bug found+fixed; corpus
  kept at `fuzz/corpus/verify_parse/`).
- `cargo clippy --all-targets`: exit 0 under `deny(warnings)` (audited
  allows in `src/lib.rs` + notation allows in `tests/prove_verify.rs`).
- `cargo fmt --check`: clean. `cargo build --no-default-features`: OK.
- Bench (release, x86_64 — full table, Q9):
  `PROOF_BYTES = 4577`; `size_of`: Proof=4577 MatrixA=8192 Poly=256
  Transcript=32; mul/small naive p50=4497ns vs nwc p50=4224ns; hash/0
  p50=139ns … hash/32768 p50=53790ns; prove min=144us p50=184us p99=420us
  max=462us (n=200); verifier min=78us p50=80us p99=83us max=86us
  (n=200, post S1+S2). p99 spread on prove (≈2.3× p50) is the retry channel R1
  (`docs/ct-audit.md`); verifier tight (1.1×). Release bench binary
  ≈ 490 KB; `no_std` builds green on `thumbv7em-none-eabihf` +
  `wasm32-unknown-unknown`. MSRV: stable 1.97 only (prototype bar).
- Bugs found by tests (published): XOF 2048-cap vs matrix expansion
  (fixed: per-poly streams), gadget `30→31` bits (`Q > 2^30`), norm
  accumulator overflow (two-pass gate), mask malleability heritage
  (all fields bound into challenges), model version hardcode (F22, caught
  by differential), `v`-variance leak (F21, wire value removed).

## Hypothesis verdicts (v0.1 prototype, Build A revision)

- H1: PASS (roundtrips across salts).
- H2: PASS for linear/binding (grind-bound `≈2^-130`, sweeps green);
  packing closes via extraction (`docs/extraction.md`, `tiny_extract`
  488/488) with quantified opens O1/O2 — PARTIAL label retired.
- H3: STRONG conditional (accepted responses exactly uniform, χ²-pinned;
  `v` wire value removed after variance finding F21); computational
  hiding marginal (`2^38–2^42`).
- H4: PASS (`4577 B`; prover p50 `184us`, verifier p50 `80us`).

## Per-phase gates (status, Build B)

- P2 ring/NTT: PASS (bitwise differential + order/roundtrip/linearity +
  NWC invertibility + 200-pair measurement).
- P3 hash: PASS (11/11 KATs + mutation suite, re-run in-model).
- P4 commit: PASS (determinism, linearity, gadget roundtrip).
- P5 core: PASS (completeness + refusal paths; rate measured P7).
- P6 verifier: PASS (roundtrips + wrong-`y`/`t` + tamper + bitflip sweep).
- P7 ZK audit: PASS (acceptance band, shift premise, joint-TV pin
  `8192/131073 < 2^-4`, salt discipline; `R∞ = ∞` recorded).
- P8 red-team: PASS (gap demo, edges, grinding floor, norm-smuggle,
  versions, salt determinism).
- Q1 extraction: PASS (`docs/extraction.md`, tiny model 488/488, O1–O3
  exact statements).
- Q2 whitepaper: PASS (`docs/whitepaper.md`, Theorems 1–3, open-lemma
  list with zero unlabeled items).
- Q3 Rényi: PASS (`tools/renyi.py` exact table + pinned test).
- Q4 estimator: PASS (`tools/svp_estimate.py` self-validating +
  `docs/lattice-margin.md`; verdict MARGINAL on hiding, recorded).
- Q5 second implementation: PASS (`tools/model.py`, 2/2 byte-identical
  via `tools/diff_vectors.py`, pinned by `tests/model_diff.rs`).
- Q6 tiny exhaustive: PASS (24 challenges enumerated, all 552 pairs
  through the extractor, boundary edges).
- Q7 fuzzing: PASS (`cargo-fuzz` 14.9 M runs/0 crashes on v0.3.0 (+34 M prior) + in-tree 2000-case
  sweep + transcript fuzz, all green).
- Q8 timing: PASS (constant-scan `response_ok`, branchless `centered`,
  Welch nulls 0.64/0.76, `docs/ct-audit.md` with 3 accepted residuals).
- Q9 benches: PASS (distributions + hash table + type sizes above).
- Q10 self-audit: PASS (spec↔code map + 20 findings, `docs/audit-log.md`).
- Q11 release: `0.3.0`, CHANGELOG, SBOM (`sbom.json`, 0 third-party),
  deterministic rlib rebuilds identical, `zero-sq` archived.
- Q12 docs: `missing_docs`/`missing_debug_implementations` deny clean,
  professional README, cross builds green.
- P9 release: bench table above; `docs/negative-results.md` current.

## Raw logs

Paste `cargo test` + bench output below each release. No editing of failures.
