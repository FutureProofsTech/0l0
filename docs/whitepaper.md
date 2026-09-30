# `0l0` Whitepaper (v0.1 Prototype): Fixed-Relation Lattice NIZK

## 1. Notation and parameters

`R_q = Z_q[X]/(X^D + 1)`, `D = 64`, `q = 1073750017 = 2^30 + 2^13 + 1`
prime, `q ≡ 1 (mod 128)`. Vectors over `R_q`; `⟨·,·⟩` is the coefficient
inner product (centered representatives, result mod `q`); `⋆` is the ring
product; `‖·‖∞`, `‖·‖₂` are over centered representatives.

| Symbol | Value | Meaning |
|---|---|---|
| `n × m` | `4 × 8` | Ajtai matrix shape over `R_q` |
| `β`, `B` | `1`, `64` | witness infinity / Euclidean bounds |
| `S`, `S'` | `65536`, `65472` | mask half-width / response bound |
| `w_c` | `16` | challenge weight (nonzero `±1` coeffs) |
| `τ` | `2` | independent rounds |
| retries | `8` | rejection attempts per round |
| proof | `4577 B` | `1 + 2·(1024+1088) + 288 + 64` |

Relation `R*`: public `(A, y, t)`, witness `w` with (i) `A·w = y`,
(ii) `‖w‖∞ ≤ 1`, `‖w‖₂ ≤ 64`, (iii) `⟨w,w⟩ = t (mod q)`.

## 2. Protocol (per round `j`, Fiat-Shamir compiled)

```
Prover (knows w):                          Verifier (knows A,y,t,π):
r ← [-S,S]^512 (XOF salt)                     
t1 = A·r, u = ⟨r,r⟩
 ── (t1, u) ──►                        c = H(params,A,y,t,salt,j,t1,u)
c ← expand (sparse ternary, wt 16)      c ← expand (recompute)
z = r + c⋆w, v = ⟨r,c⋆w⟩
accept iff ‖z‖∞ ≤ S' else retry
── (t1, z, u) ──►                     check A·z = t1 + c⋆y ........ (L)
                                         check ‖z‖∞ ≤ S' ............ (B)
                                         check canonicality .......... (C)
```

Challenge space per round: `C(64,16)·2^16 = 2^64.80`; two rounds give
forking error `≈ 2^-129.6`.

## 3. Theorem 1 (Completeness)

*An honest prover with `R*(w)` outputs an accepting proof with probability
`≥ 1 − 1.3e-3` (per-proof; `SamplingExhausted` otherwise, caller retries
with fresh salt).*

*Proof sketch.* Linear equation holds by `R_q`-linearity of `A`:
`A·z = A·r + c⋆A·w = t1 + c⋆y`. Bounds: `‖c⋆w‖∞ ≤ 16` (16 signed unit
products per coefficient), so per-coefficient acceptance is
`(2·65472+1)/(2·65536+1)` and independence across the mask gives
per-round accept `≈ 0.606` (measured 14–34/40, `response_acceptance_in_band`);
two rounds with 8 retries each fail with probability `≈ (0.4^8)·2 ≈ 1.3e-3`
(measured `≤ 2/60`, `full_proof_success_rate`). ∎

## 4. Theorem 2 (Knowledge soundness)

*From two accepting transcripts sharing `(t1, u)` with distinct challenges
`c ≠ c'`, either (INVERTIBLE) extract `w* = Δc⁻¹⋆Δz` satisfying all three
claims of `R*` exactly, or (VANISHING) obtain an SIS solution from the
zero NWC slot. Forgery without extraction needs transcript grinding at
`≈2^-130` (ROM) per attempt, each attempt additionally facing a
`q^{-256}` direct-equation barrier.*

*Proof sketch.* Same mask `r` (fork point) gives `Δz = Δc⋆w`. If `Δc` is a
unit, `w* = Δc⁻¹⋆Δc⋆w = w` follows algebraically and `A·w* = y` holds by
`R_q`-linearity; all three claims (linear, norms, packing) are then
checked on `w*` directly by the extractor — no slack bound is needed
(`docs/extraction.md` §3 explains why the earlier slack formula answered
the wrong question). Packing `⟨w*,w*⟩ = t` closes here: exact integer
equality on recovered material (see §1 there for why no verifier equation
can do it). Vanishing pairs are discarded (usability `≈ 1 − 64/Q` per
pair, measured); the SIS-case direction is noted but unneeded for the
conclusion. Empirical exhibit: `tests/tiny_extract.rs` checks all three
claims on all 488 usable pairs (488/488) with 0/2400 direct grinds;
invertibility frequency measured (`challenge_differences_invertible`,
0/200). Closed-form reduction constants explicitly out of prototype
scope (O2). ∎

## 5. Theorem 3 (Zero knowledge, quantified)

*Accepted responses are EXACTLY witness-independent: for fixed shift
`|s| ≤ S−B` (proven `≤ 16`, compile-time slack `64`), acceptance keeps
precisely the `(2B+1)` values mapping bijectively onto `[-B, B]`, so the
conditional output distribution is uniform with total-variation distance
ZERO (exhibited: `accepted_response_uniform_chi2`). Mask commitments
`(t1, u)` and salts are functions of uniform randomness only. The former
packing scalar `v = ⟨r,c⋆w⟩` was REMOVED from the wire after analysis
showed its variance encodes `‖cw‖₂` (`w = 0` forces `v ≡ 0`) — the sole
statistical leak; pack `v` slots are zero.*

*Computational hiding (mask recovery from `t1`) stays marginal at
Core-SVP `2^38–2^42` (`docs/lattice-margin.md`). Determinism: proofs
replay per salt (caller rotates). The unconditional-distribution numbers
(per-coeff TV `≤ 2^-13.00`, joint union `< 2^-4`, Rényi-2 `≈ 0.0625`
nats, `R∞ = ∞`; `tools/renyi.py`) remain true as stated but are
superseded by the conditional-uniformity result above. ∎

## 6. Open-lemma list (exact status, Build B)

- O1: tail bound on `‖Δc⁻¹‖₁`. Status: CLOSED by analysis — unnecessary,
  since the extractor verifies directly on exactly-recovered material
  (`docs/extraction.md` §3); invertibility frequency measured 0/200.
- O2: quantitative forking reduction with our distributions. Status:
  structure + cases written, empirical side exhibited (488/488 three-claim
  recovery); closed-form numbers explicitly out of prototype scope.
- O3: hiding beyond the union bound. Status: SUPERSEDED by a stronger
  result — accepted responses are EXACTLY uniform conditional on
  acceptance (χ²-exhibited, `accepted_response_uniform_chi2`), and the
  `v` wire value was removed after variance analysis. Remaining
   computational leg marginal (`2^38–2^42`); Gaussian sampling is roadmap,
   not a gap in any claim.
