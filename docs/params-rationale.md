# `0l0` Params Rationale (P0 — what is frozen and why)

## Ring `(D=64, Q=1073750017)`

- `D = 64`: power of two giving 512 witness coefficients with `M_COLS = 8`,
  so naive `O(D²)` products stay test-friendly while the NTT has a clean
  size-64 target. Larger `D` is a named follow-up.
- `Q = 1073750017 = 2^30 + 2^13 + 1`: prime, fits `u32`, products of two
  `< q` values fit `u64`, `Q ≡ 1 (mod 128)` so primitive 64-th roots of unity
  exist for the from-scratch NTT. `Q/2`-centered representatives give clean
  `±1` ternary checks.
- NOT claimed: that `(64, ~2^30, ternary)` meets any named NIST level.
  The margin is measured, not blessed: `tools/svp_estimate.py` (Core-SVP,
  self-validating) reports response-kernel `2^27–2^30`, mask `2^38–2^42`,
  ternary-witness below estimator floor — see `docs/lattice-margin.md`
  for the honest reading (forgery still grind-bound; hiding marginal).

## Witness `(8 polys, ternary)` and bounds `(β=1, B=64)`

- 8 ternary polys = 512 coefficients, `‖w‖_2 ≤ √512 ≈ 22.6 < 64`: honest
  witnesses pass with ~3× margin; forgeries must smuggle visibly large
  coefficients. `β+1`/`B+1` edges are red-team cases (P8).
- `N_ROWS = 4`: commitment `4×64×4 B = 1024 B`; narrower would weaken
  binding per SIS folklore, wider would blow the 10 KB envelope.

## Soundness shaping (`TAU=2` weight-16 challenges, uniform masks, 8 retries)

- Challenge: sparse ternary polynomials, weight 16 over 64 coefficients →
  space `C(64,16)·2^16 ≈ 2^64.8` per round, `≈2^-130` grind-resistance over
  two rounds (ROM, pinned by `grinding_space_floor`). The extraction-slack
  formula is explicit (`docs/extraction.md` §3); its inverse-norm tail is
  quantified open item O1. The `≈2^-100` pre-registered target is met by
  the grind bound with margin.
- Masks uniform in `[-65536, 65536]`, responses accepted to `65472`
  (slack 64 covers `‖c⋆w‖_∞ ≤ 16` with margin, compile-time asserted).
  8 fixed retries bound prover effort deterministically (no heap, no RNG
  trait — salt-derivation in the prover).
- Hiding measured exactly (`tools/renyi.py`): joint TV `< 2^-4`, verdict
  MARGINAL — see `docs/lattice-margin.md`, not a claim of strength here.

## Budget (`4577 B` of `2048..10240`)

- Per round `t1 (1024 B) ‖ z (1088 B packed)` ×2 rounds + packing block
  (`u0 0 u1 0` + reserved, 288 B) + challenge block (salt + reserved,
  64 B) + 1 version byte = `4577 B` (compile-time asserted). Responses
  still dominate (packed 17-bit words are information-theoretically tight
  for ±65472 coefficients); recursion would shrink openings further but
  grow audit surface — deferred past prototype.
