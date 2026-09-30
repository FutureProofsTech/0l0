# `0l0` Negative Results & Open Problems (Build A revision)

## Closed since the `zero-sq` toy

- Linear soundness mechanism: commit → challenge → respond → verify, with
  grinding-bound challenges (`≈2^-130` over two rounds, ROM) instead of the
  toy's publicly re-derivable walk. Wrong-`y`/`t`, tamper, and 65-position
  bitflip sweeps all reject.
- Packing exact equality: closed through knowledge-soundness extraction
  (`docs/extraction.md` + `tests/tiny_extract.rs` at 488/488), replacing
  the v0.1 PARTIAL label. The kernel-ambiguity argument (§1 there) records
  WHY no verifier equation could do it — the gap is closed by the
  extractor, not hidden.
- Transcript binds every proof field plus frozen params and version.
- Norm accumulator overflow (two-pass gate), gadget bit-length, XOF-cap
  matrix expansion, cyclic-vs-negacyclic invertibility test (wrong-ring
  failure at pair 3 caught and corrected — §6 of extraction doc).
- Fuzz harness bug (test-side slice panic) caught by `cargo-fuzz` in
  minutes; full Miri lib run logged (see results).

## Demonstrated gaps (with exhibiting tests, not just prose)

1. **Extraction, O1 closed / O2 scoped** (`docs/extraction.md` §5 +
   `docs/whitepaper.md` §4/§6): the inverse-norm tail dissolved on
   analysis — the extractor verifies directly on exactly-recovered
   material, so no tail bound is needed; invertibility itself is measured
   (0/200). Closed-form reduction constants explicitly out of scope.
2. **Hiding: statistical leg now PERFECT-conditional, computational leg
   marginal** — accepted responses are exactly uniform on `[-B,B]^512`
   (χ²-exhibited, `accepted_response_uniform_chi2`); the former `v` wire
   value was REMOVED after variance analysis showed it encoded `‖cw‖₂`
   (the sole statistical leak). Remaining: Core-SVP mask leg `2^38–2^42`
   (`docs/lattice-margin.md`) and Gaussian sampling as roadmap (no longer
   needed for statistical hiding).
3. **Parameter strength**: Core-SVP reimplementation (closed-form δ(β)),
   not BKZ simulation; module-lattice (slot-wise) attack surface for the
   splitting-friendly `q` unreviewed. Follow-up specified in the memo.
4. **Side channels**: timing discipline documented-effort only (timing
   harness is Build C); microarch oracles accepted.

## Explicitly out of scope (not gaps — never claimed)

General circuits/VM, recursion, proof aggregation, sub-900 B proofs,
post-quantum reduction proofs, external audit, formal methods, `no_std`
hardware targets beyond build-checks, CVE process.
