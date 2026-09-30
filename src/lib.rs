// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! `0l0` — production-prototype lattice-concise post-quantum NIZK.
//!
//! Fixed application relation `R*` over `R_q = Z_q[X]/(X^d+1)` with a
//! LaBRADOR-style single-level witness reduction. See `docs/spec.md`.
//!
//! # Honesty notice
//! Prototype bar only: no external audit, no reduction proof, LaBRADOR-family
//! cryptanalysis is young. All limits and negative results are published in
//! `docs/results.md`. Not production.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
// Audited style-debt allows (no security impact; see docs/results.md):
// - `needless_range_loop`: fixed-array index loops are intentional for
//   stack-only `no_std` code with explicit bounds.
// - `many_single_char_names`: ring/matrix `(a,b,q,d,m,n)` notation follows
//   the lattice literature.
// - `cast_possible_truncation` / `cast_possible_wrap` / `cast_sign_loss`:
//   remaining `as` casts are on provably bounded values (coeffs `< q`,
//   indices `< d`, `0/1` bits, `±1` squares); each site carries a comment.
// - `missing_const_for_fn`: const-ification is a P9 perf pass; stub
//   signatures intentionally match their future real (non-const) bodies.
// - `assertions_on_constants`: `params`/`proof` compile-time asserts check
//   the frozen spec values on purpose.
#![allow(
    clippy::needless_range_loop,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_const_for_fn,
    clippy::assertions_on_constants
)]

pub mod commit;
pub mod error;
pub mod hash;
pub mod params;
pub mod proof;
pub mod prover;
pub mod ring;
pub mod transcript;
pub mod verifier;

/// Crate version string.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
