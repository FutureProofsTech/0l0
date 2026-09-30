# Lattice Margin Memo (Q4 — Core-SVP estimates, prototype bar)

Measured 2026-09-30 via `tools/svp_estimate.py` (self-validating: aborts on
param drift). Model: standard Core-SVP (BKZ-`β` root-Hermite factor
Chen–Nguyen, costs `2^{0.292β}` classical / `2^{0.265β}` quantum) on the SIS
lattice `Λ = {x : A·x = 0}` (dim 512, `log2(det) = 7680`, GH ≈ 179411).

```
response-level kernel   B=   2962924  beta= 104  classical 2^30.4  quantum 2^27.6
mask recovery           B=   1482910  beta= 145  classical 2^42.3  quantum 2^38.4
ternary witness         B=        23  beta= 512 (>=512 floor)  classical 2^149.5  quantum 2^135.7
RESULT MARGINAL
```

Cross-validation (same script, `bkz_tour_simulate`, 30 tours, simplified
Chen–Nguyen profile dynamics, teaching-grade — validates ORDER, not
constants): simulated shortest vs closed-form shortest vectors agree to
1–3% (`β=104: 2955434 vs 2920273`; `β=145: 1481929 vs 1468311`;
`β=200: 797368 vs 776383`). The closed-form costs above are therefore
not a formula artifact; a second dynamical computation lands in the same
place.

## Reading these numbers honestly

- **Forgery is NOT broken by the β=104 leg.** A short kernel vector alone
  forges nothing: every forgery attempt must *also* satisfy the transcript
  equation for a fresh challenge (grind `≈2^-130` over two rounds) with a
  per-attempt ISIS preimage at mask-recovery cost. Defense in depth holds:
  grinding-bound × ISIS-per-attempt.
- **Hiding IS marginal** (the headline): mask recovery at `2^38–2^42` is
  within reach of well-funded attackers, and recovering `r` from
  `t1 = A·r` exposes `w = c⁻¹⋆(z−r)`. This agrees with the independent
  Rényi finding (joint statistical edge `≈2^-4`). Prototype verdict:
  soundness/binding acceptable at prototype bar; **hiding is not
  production-grade** — follow-up is Gaussian sampling with Rényi analysis
  and/or larger `S` (with re-measured acceptance `M`).
- **Secret recovery is strong** (`≥ floor`): ternary `w` sits below the
  Gaussian heuristic; the estimator cannot even resolve it (full-dimension
  regime). No exact figure is claimed — the `2^149.5` is the floor cap,
  labeled as such in the script output.

## What would change the verdict

Estimator pass with BKZ simulators (G6K-style) instead of closed-form
δ(β); module-lattice (algebraic) attack surface review for `R_q` with
`q ≡ 1 (mod 128)` (the splitting that enables our NTT also enables
slot-wise attacks — currently unreviewed, explicitly listed); fresh
measurement after any parameter change (script aborts on drift by design).
