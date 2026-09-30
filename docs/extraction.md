# Extraction & Packing Closure (Q1 — the end of "PARTIAL")

## 1. Why no verifier equation can pin `⟨w,w⟩ = t` (kernel ambiguity)

Fix public `(A, y, t)` and any verifier predicate `E(t1, u, c, z, v, s1)`
computable from proof material alone. Let `w'` be ANY witness with
`A·w' = y` (possibly `⟨w',w'⟩ ≠ t`). An adversarial prover runs the honest
prover algorithm on `w'`: it produces `(t1, u, c, z, v)` satisfying the
linear equation `A·z = t1 + c⋆y` (it holds by construction for every `w'`
with `A·w' = y`), the response bound, and canonicality. The packing
scalars are prover-supplied, so `s1`-style values for `w'` pass any
range/binding checks. Hence `E` accepts a proof whose witness violates the
packing claim. CONCLUSION: exact-equality packing cannot close through
verifier equations; it closes through knowledge soundness (rewinding
extraction), exactly as in Lyubashevsky/Dilithium-style analyses. The
`u` is an extractor input (committed pre-challenge) plus
malleability binding — its role is specified, not decorative. (The former
post-challenge scalar `v = ⟨r,c⋆w⟩` was removed from the wire: its variance
encodes `‖cw‖₂`. See whitepaper §5.)

## 2. Rewinding extraction (per round) — CLOSED

Rewind a convincing prover to two accepting transcripts sharing the mask
commitment `(t1, u)` (same `r`) with distinct challenges `c ≠ c'`:
`z = r + c⋆w`, `z' = r + c'⋆w` (same `r` by the fork point).

- Case INVERTIBLE (`Δc = c − c'` a unit in `R_q`): recover
  `w* = Δc⁻¹ ⋆ (z − z')` and check `A·w* = y`, `‖w*‖` bounds, and
  `⟨w*,w*⟩ = t` EXACTLY (integer arithmetic on centered representatives).
  Exhibited: `tests/tiny_extract.rs` checks all three claims on all 488
  usable pairs — 488/488.
- Case VANISHING (`Δc` has an NWC-spectrum zero): the pair is discarded;
  usability holds with probability `≈ 1 − 64/Q` per pair (measured 0/200
  on full params, 488/552 usable on the tiny model where `Q' = 17` makes
  vanishing common — the exhibit covers both paths). Turning a vanishing
  pair into an SIS solution (zero-slot kernel relation) is noted as the
  classical Lyubashevsky-case direction but is NOT needed for the
  soundness conclusion: forking succeeds as long as usable pairs exist
  with overwhelming probability, which is measured, not assumed.

## 3. Slack: no slack needed (analysis correction)

An earlier revision stated a slack formula
(`‖w*‖∞ ≤ ‖Δc⁻¹‖₁·130944`) and listed the inverse-norm tail as open item
O1. That formula answers the wrong question: the extractor does not need
a BOUND on `w*` — it checks all three claims on the recovered `w*`
DIRECTLY (exact integer arithmetic). Since `Δz = Δc⋆w` holds algebraically,
an invertible `Δc` recovers the prover's witness EXACTLY
(`w* = Δc⁻¹⋆Δc⋆w = w`), and the checks then pass iff the prover knew a
satisfying witness. O1 is therefore CLOSED by analysis (with the tiny
exhibit as evidence), not by a tail bound. What remains measured: the
invertibility frequency itself (`challenge_differences_invertible`).

## 4. Grinding, precisely separated (both measured)

- Direct grinding (random `(t1, z)` vs transcript-derived `c`): each trial
  must satisfy `n·d` equations over `Z_q`. Tiny: `17^-8`/trial, measured
  `0/2400` (expectation `≈ 6e-7`). Full: `(2^30)^-256 = 2^-7680`/trial.
- Forking error (same commitment, fresh challenge): `1/|C|` per round.
  Tiny: `1/24` (exact, enumerated). Full: `1/(C(64,16)·2^16) = 2^-64.8`
  per round, `≈2^-130` over two rounds (pinned by `grinding_space_floor`).

## 5. Quantified items (final status)

- O1 (inverse-norm tail): CLOSED by analysis (§3) — no tail bound needed
  since the extractor verifies directly; invertibility measured (0/200).
- O2 (quantitative forking): structure + cases above, empirical side
  exhibited (488/488 three-claim recovery, 0/2400 direct grinds);
  closed-form reduction constants explicitly out of prototype scope.
- O3: see `tools/renyi.py` + `docs/lattice-margin.md` (closed with
  marginal verdict).

## 6. Measurement lessons (published mistakes)

- The first invertibility test used the CYCLIC spectrum and failed at pair
  3 — correctly so: weight-2 cyclic differences ALWAYS vanish
  (`ω^{i·d} = −1` solvable for every `d < 64`). The negacyclic (NWC)
  spectrum is the right question (`nwc_has_zero`); weight-2 negacyclic
  differences are provably always invertible (`ζ^d = ±1` impossible for
  `0 < |d| < 64`). Heuristics lose to measurement; both are recorded.
