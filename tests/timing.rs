// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Timing discipline harness (Q8): Welch t-tests + distribution report.
//!
//! Smoke-level (shared dev machine, not a lab): thresholds separate
//! null (|t| < 10) from real position-dependent effects (|t| in the
//! hundreds, as the pre-fix early-exit showed). See `docs/ct-audit.md`.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::many_single_char_names)]
// Sample lengths are <= 300 << 2^52: `as f64` conversions are exact.
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

use sq_pq::params::{M_COLS, Q, RESP_BOUND};
use sq_pq::prover::response_ok;
use sq_pq::ring::{poly_mul_nwc, Poly};
use std::time::Instant;

fn welch(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let (ma, mb) = (mean(a), mean(b));
    let va = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>() / (a.len() - 1) as f64;
    let vb = b.iter().map(|x| (x - mb).powi(2)).sum::<f64>() / (b.len() - 1) as f64;
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

fn time_it(f: impl Fn()) -> f64 {
    let t0 = Instant::now();
    f();
    t0.elapsed().as_nanos() as f64
}

/// Null control: field products must not depend on coefficient values
/// (fixed loop bounds, branchless reduction).
#[test]
fn nwc_timing_independent_of_values() {
    let zero: Poly = [0; 64];
    let max: Poly = [Q - 1; 64];
    // Warmup.
    for _ in 0..50 {
        std::hint::black_box(poly_mul_nwc(&zero, &max));
    }
    let mut ta: Vec<f64> = Vec::with_capacity(300);
    let mut tb: Vec<f64> = Vec::with_capacity(300);
    for _ in 0..300 {
        ta.push(time_it(|| {
            std::hint::black_box(poly_mul_nwc(&zero, &zero));
        }));
        tb.push(time_it(|| {
            std::hint::black_box(poly_mul_nwc(&max, &max));
        }));
    }
    let t: f64 = welch(&ta, &tb).abs();
    eprintln!("nwc zero-vs-max Welch t = {t:.2}");
    assert!(t < 10.0, "timing depends on values?");
}

/// The Q8 fix: rejection position must not affect scan time (constant scan).
/// Pre-fix early exit gave |t| in the hundreds here by construction.
#[test]
fn response_scan_position_independent() {
    let mut first_bad: [Poly; M_COLS] = [[0; 64]; M_COLS];
    first_bad[0][0] = RESP_BOUND + 1;
    let mut last_bad: [Poly; M_COLS] = [[0; 64]; M_COLS];
    last_bad[M_COLS - 1][63] = RESP_BOUND + 1;
    assert!(!response_ok(&first_bad) && !response_ok(&last_bad));
    for _ in 0..50 {
        std::hint::black_box(response_ok(&first_bad));
    }
    let mut ta: Vec<f64> = Vec::with_capacity(300);
    let mut tb: Vec<f64> = Vec::with_capacity(300);
    for _ in 0..300 {
        ta.push(time_it(|| {
            std::hint::black_box(response_ok(&first_bad));
        }));
        tb.push(time_it(|| {
            std::hint::black_box(response_ok(&last_bad));
        }));
    }
    let t: f64 = welch(&ta, &tb).abs();
    eprintln!("response first-vs-last-bad Welch t = {t:.2}");
    assert!(t < 10.0, "scan time depends on bad-coeff position?");
}

/// Informational: full-prove latency distribution (documents the residual
/// attempt-count channel magnitude for `docs/ct-audit.md`).
#[test]
fn prove_latency_distribution() {
    use sq_pq::commit::derive_matrix;
    use sq_pq::prover::{prove, sample_witness_for};
    let a = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t) = sample_witness_for(&a, &[22; 32]);
    let mut dt: Vec<f64> = Vec::with_capacity(40);
    for i in 0..40u32 {
        let mut salt: [u8; 32] = [0x77; 32];
        salt[..4].copy_from_slice(&i.to_le_bytes());
        let t0 = Instant::now();
        let _ = prove(&a, &w, &y, t, &salt).expect("prove");
        dt.push(t0.elapsed().as_micros() as f64);
    }
    dt.sort_by(|x, y| x.partial_cmp(y).expect("finite"));
    eprintln!(
        "prove us: min={:.0} p50={:.0} max={:.0} (n=40, dev profile)",
        dt[0], dt[20], dt[39]
    );
    assert!(dt[39] < 5_000_000.0, "prove pathologically slow?");
}
