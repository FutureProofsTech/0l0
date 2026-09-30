# 0l0 — Lattice-Concise Post-Quantum Non-Interactive Zero-Knowledge Proofs

A from-scratch, zero-dependency cryptographic engine in 100% safe Rust
(`#![forbid(unsafe_code)]`, `no_std`-compatible) proving knowledge of a
short witness for a fixed application relation — with 4577-byte proofs,
sub-millisecond proving and verification, and no trusted setup.

**Status: production prototype, not production.** No external audit, no
reduction proof. Every security claim ships with exhibiting evidence;
every known limit is published — start with
[`docs/negative-results.md`](docs/negative-results.md).

- **License:** GPLv3 — see [`LICENSE`](LICENSE).
- **Version:** 0.3.0 ([changelog](CHANGELOG.md), [roadmap](ROADMAP.md)).
- **Papers:** [`paper/whitepaper.pdf`](paper/whitepaper.pdf) (protocol and
  theorems) · [`paper/yellowpaper.pdf`](paper/yellowpaper.pdf) (formal
  specification).

## What it proves

Relation `R*` over `R_q = Z_q[X]/(X^64+1)` with `q = 1073750017`:
knowledge of a ternary witness `w ∈ R_q^8` such that `A·w = y`,
`‖w‖∞ ≤ 1`, `‖w‖₂ ≤ 64`, and `⟨w,w⟩ = t`. Two-round Lyubashevsky proofs
(Fiat–Shamir, BLAKE3 transcript), versioned `4577 B` wire format.

```rust
use sq_pq::commit::derive_matrix;
use sq_pq::params::PROOF_BYTES;
use sq_pq::prover::{prove, sample_witness_for};
use sq_pq::verifier::verify;

let a = derive_matrix(&[11; 32]).expect("matrix");
let (w, y, t) = sample_witness_for(&a, &[22; 32]);
let salt = [33; 32]; // caller rotates fresh salts per proof
let proof = prove(&a, &w, &y, t, &salt).expect("prove");
verify(&a, &y, t, &proof).expect("verify");
assert_eq!(proof.to_bytes().len(), PROOF_BYTES); // 4577
```

## Measured performance (x86_64, release, `cargo run --release --example bench`)

| Artifact | Value |
|---|---|
| Proof wire | `4577 B` fixed by type (commit 1024 + 2×packed-response 1088 + pack 288 + salt 64 + version) |
| Prover | p50 `184 µs`, p99 `420 µs` (n=200) |
| Verifier | p50 `80 µs`, p99 `83 µs` (n=200) |
| NWC vs naive mul (D=64) | p50 `4224 ns` vs `4497 ns` |
| BLAKE3 | 139 ns (empty) … 54 µs (32 KiB) |

## Security summary (with evidence, not adjectives)

| Claim | Evidence |
|---|---|
| Completeness | 8 e2e prove/verify tests + 60-salt success gate |
| Linear soundness (`≈2^-130` grind) | wrong-`y`/`t`, tamper, exhaustive 36,616-bitflip sweep (all reject) |
| Exact packing | extractor exhibit 488/488 (`tests/tiny_extract.rs`) + `docs/extraction.md` |
| Hash correctness | 11/11 official BLAKE3 KATs, re-run in an independent Python model |
| Second implementation | `tools/model.py` — 2/2 byte-identical proofs |
| Hiding (statistical: exact; computational: marginal) | χ² conditional-uniformity exhibit; `v` wire value removed after variance analysis; Core-SVP mask leg `2^38–2^42` |
| Memory safety | full Miri lib run green; `cargo-fuzz` 14.9 M runs, 0 crashes |
| Timing discipline | constant-scan checks, branchless field core, Welch t-test harness |

Known limits: no reduction proof (open items O1/O2 scoped in the
whitepaper), hiding computationally marginal, no lab side-channel
evaluation, no external audit. Details in
[`docs/negative-results.md`](docs/negative-results.md).

## Red-team campaign (measured, all recorded)

The brutal suite (`tests/brutal.rs`, 14 tests) attacks every feasible
vector; the full log with exact counts is
[`docs/redteam-log.md`](docs/redteam-log.md):

| Attack | Scale | Result |
|---|---|---|
| Single-bitflip forgery, exhaustive | 36,616 mutants (all bytes × all bits) | **36,616/36,616 reject** |
| Two-bit pairs | 5,000 random pairs | 5,000/5,000 reject |
| Round-block swap, cross-proof splice | 3 | all reject |
| Direct grinding on random wire | 20,000 trials | **0 accepts** |
| Exhaustion census (200 salts), sparsity classes | 280 proofs | 0 exhausted |
| Decode edges, framing, API limits, seed edges, transcript framing | 20 cases | all fail closed |
| libFuzzer (`fuzz/`, corpus kept) | 14.9 M runs, this code | 0 crashes |
| Full Miri lib run | 35/35 | green, no UB |

The campaign caught a real bug: exhaustive flipping found `v`-slot flips
that verified (finding F24) — the zeroed packing scalars were
unauthenticated. Fixed by enforcing canonical zeros at verify; every wire
byte is now functional-and-bound or enforced-zero, and both
implementations mirror the check.

## Repository map

```
src/        zero-dependency engine (ring, hash, transcript, commit, prover,
            verifier, proof, params, error)
tests/      75 tests: unit, KAT, brutal red-team (exhaustive bitflips,
            20k grinding game), audit, timing, extractor gates
tools/      independent Python model, tiny extractor, Rényi + SVP scripts
fuzz/       libFuzzer target (corpus kept)
docs/       spec, whitepaper source notes, extraction argument, threat model,
            params rationale, lattice margin, timing + self audits, results
paper/      whitepaper.pdf + yellowpaper.pdf (LaTeX sources included)
```

## Verification (all green on release day)

```sh
cargo test                                        # 75/75 (dev and --release)
cargo clippy --all-targets && cargo fmt --check  # deny(warnings), clean
cargo build --no-default-features                 # no_std
cargo build --no-default-features --target thumbv7em-none-eabihf
cargo build --no-default-features --target wasm32-unknown-unknown
cargo +nightly miri test --lib                   # 35/35 green
cargo +nightly fuzz run verify_parse -- -max_total_time=150
python3 tools/diff_vectors.py                     # byte-identical differential
python3 tools/renyi.py && python3 tools/svp_estimate.py
```

## Contributing

Bug reports with exhibiting reproducers (a failing test or script, never
prose alone) are welcome. Security-sensitive findings: please open an
issue with a minimal reproducer against the latest tagged version.
