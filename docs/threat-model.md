# `0l0` Threat Model (Prototype Bar)

## Attacker goals (red-team gates P8)

1. Forge for `(A, y, t)` without a short satisfying `w`.
2. Smuggle `‖w‖_∞ = β+1` or `‖w‖_2 = B+1` past the norm opening.
3. Malleate a valid proof (bitflip → still accept).
4. Grind Fiat-Shamir (omit/bind fields for favorable challenges).
5. Replay a proof under different `(y, t)` or ring params.
6. Distinguish witnesses across proofs (ZK break: response statistics,
   packing-scalar variance (CLOSED — `v` removed), rejection-rate,
   salt reuse across proofs).
7. Swap `A` (weak matrix) or downgrade `version`.

## What v0.1 enforces (P6 verifier)

Strict version check, canonical parsing (no trailing bytes, coefficients
`< q`), transcript binding of *all* public inputs including the frozen
`(D, Q, β, B)` params block and proof `version`, Ajtai + response + packing
openings, challenge recomputation.

## Assumptions (explicit, not proven here)

- SIS/LWE-style hardness of the concrete `(D=64, q≈2^30, ternary)` Ajtai
  instance; LaBRADOR-family analysis is young — parameters carry a
  cryptanalysis-risk margin note, not a reduction proof.
- BLAKE3-32 core spec-exact (KATs); XOF cascade assumed PRF (documented
  deviation from official seek mode).
- Accepted responses are exactly uniform on `[-B,B]^512` (χ²-exhibited),
  `u`/salts carry no witness signal, and the leaky `v` wire value was
  removed; hiding-distance bounds are recorded exactly (`tools/renyi.py`
  for the unconditional distributions). Computational hiding rests on
  mask recovery (Core-SVP `2^38–2^42`, MARGINAL — not production-grade).

## Accepted risks (do not file as bugs)

- No external audit; no formal methods; NTT/sampling timing discipline is
  documented-effort only (microarch oracles accepted).
- Deterministic builds/`no_std` are best-effort (SBOM stub, no CVE process).
- Single fixed relation: no VM, no recursion, no gadget composition beyond
  what compiles to `R*`.

## Misuse (DON'T)

- DON'T use for production, money, identity, or consensus.
- DON'T change `(D, Q, β, B, TAU)` or the mask/challenge bounds without
  re-running KATs + adversarial suite + updating `params-rationale.md`.
- DON'T strip `version` or truncate proofs (`4577 B` exact, v2 only — v1 stopped verifying at the cutover).
