# `0l0` v0.1 Spec Freeze (P0) — Fixed Relation `R*`, LaBRADOR-Style

Status: prototype. Not production. See `threat-model.md`, `results.md`.

## 1. Relation `R*`

Public: Ajtai matrix `A ∈ R_q^{4×8}`, commitment `y = A·w`, scalar `t`.
Witness: `w ∈ R_q^8` with coefficients in `{-1, 0, 1}` (`‖w‖_∞ ≤ 1`).

- Linear: `A·w = y` over `R_q = Z_q[X]/(X^64+1)`, `q = 1_073_750_017`.
- Shortness: `‖w‖_∞ ≤ 1`, `‖w‖_2 ≤ 64`.
- Packing: `⟨w,w⟩ = t (mod q)` over centered representatives.

Ground truth: `prover::check_relation` (naive, auditable). The P5 prover and
P6 verifier must agree with it bitwise.

## 2. Ring

`q = 1073750017` is prime with `q ≡ 1 (mod 128)`: 64-th roots of unity exist,
so the P2 NTT (size 64, from scratch) is well-defined. Products use `u64`
(`Z_q`) / `i128` (negacyclic accumulation: `±2^66 << 2^127`, exact).

## 3. Hash + transcript

BLAKE3-32 re-implemented from scratch in P3 (11 official KATs re-run from
the `zero-sq` design). Hedged Fiat-Shamir binds domain, ring params, `A`,
`y`, `t`, commitment, and every opening. XOF is the documented
`hash(input‖tag‖LE64 ctr)` cascade, not official `compress_xof` seek mode.

## 4. Proof core (P5, Lyubashevsky, two rounds)

Per round: short uniform mask `r ∈ [-65536, 65536]^512`, commitment
`t1 = A·r`, packing scalar `u = ⟨r,r⟩`, transcript challenge `c` (sparse
ternary, weight 16, `≈2^-65` grind-resistance per round), response
`z = r + c⋆w` with rejection on `‖z‖_∞ ≤ 65472`. Accepted responses are
exactly uniform on `[-B,B]^512` (χ²-exhibited); the former `v = ⟨r,c⋆w⟩`
slots are zero — analysis showed its variance encodes `‖cw‖₂`, so it was
removed rather than shipped leaky. Verifier checks `A·z = t1 + c⋆y` +
response bounds + canonicality + transcript binding. Exact packing `⟨w,w⟩ = t` closes
through knowledge-soundness extraction (`docs/extraction.md`: rewind to
two transcripts, recover `w*`, check all three claims — exhibited on the
tiny model at 488/488), NOT through a verifier equation (impossible by
the kernel-ambiguity argument, §1 there). `u` is an extractor input
plus malleability binding. Forgery without a satisfying witness must
grind the transcript (`≈2^-130` over two rounds, ROM) or break SIS.
Hiding-distance numbers are quantified (O3, closed marginal); the only
analytic remainder is closed-form reduction constants (O2, out of scope).

## 5. Wire (v2, `4577 B`)

`version:u8 (=2)` + per round `t1 (1024 B) ‖ z (1088 B, 17-bit packed)` ×2 + packing block
(`u0 0 u1 0` + reserved, 288 B) + challenge block (master salt + reserved,
64 B) = `4577 B` total (`PROOF_BYTES`, compile-time asserted inside
`[2048, 10240]`).

## 6. Pre-registered hypotheses (v0.1 verdicts)

- H1 completeness: honest ternary `w` always verifies. ✅ (roundtrips green)
- H2 soundness: linear forgery must grind `≈2^-130` (wrong-`y`/`t`,
  tamper, bitflip sweeps all reject); packing closes via extraction
  (`tests/tiny_extract.rs` 488/488 three-claim, `docs/extraction.md`). ✅
  (O1 closed by analysis; O2 closed-form constants out of scope).
- H3 ZK: accepted responses exactly uniform (χ² exhibit); `v` removed
  after variance analysis; computational hiding marginal (`2^38–2^42`);
  deterministic per salt (caller rotates).
- H4 perf/size: `4577 B` fixed; prover p50 `184 µs` (p99 `420 µs`),
  verifier p50 `80 µs` (p99 `83 µs`).
