// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Full benchmark suite (Q9): distributions, microbench matrix, type sizes.
//!
//! Prints: proof budget, NTT-vs-naive matrix, hash-size table, prove/verify
//! latency distributions (min/p50/p99/max, N=200, release), and the largest
//! stack-resident types (`size_of`, static frame analysis input).

// Bench harness: single-char lattice names; nanos-to-f64 exact for any
// realistic run (< 2^53 ns); small-index casts bounded by construction.
#![allow(clippy::many_single_char_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::missing_panics_doc)]

use sq_pq::commit::derive_matrix;
use sq_pq::hash::hash;
use sq_pq::params::{CHALLENGE_BYTES, COMMIT_BYTES, PROOF_BYTES, QUAD_OPEN_BYTES, Z_BYTES};
use sq_pq::prover::{prove, sample_witness_for};
use sq_pq::ring::{poly_mul_naive, poly_mul_nwc, Poly, NCOEFFS};
use sq_pq::verifier::verify;
use std::time::Instant;

fn stats(mut v: Vec<f64>) -> (f64, f64, f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let q = |p: f64| v[((v.len() as f64 * p) as usize).min(v.len() - 1)];
    (v[0], q(0.5), q(0.99), v[v.len() - 1])
}

fn main() {
    println!("PROOF_BYTES = {PROOF_BYTES}");
    println!("  commit   = {COMMIT_BYTES}");
    println!("  response = {Z_BYTES}");
    println!("  quad     = {QUAD_OPEN_BYTES}");
    println!("  chal     = {CHALLENGE_BYTES}");
    const { assert!(PROOF_BYTES <= 10_240 && PROOF_BYTES >= 2048) };
    println!(
        "size_of: Proof={} MatrixA={} Poly={} Transcript={}",
        core::mem::size_of::<sq_pq::proof::Proof>(),
        core::mem::size_of::<sq_pq::commit::MatrixA>(),
        core::mem::size_of::<Poly>(),
        core::mem::size_of::<sq_pq::transcript::Transcript>(),
    );

    // Microbench matrix: ring products across input classes.
    let mut a: Poly = [0; NCOEFFS];
    let mut b: Poly = [0; NCOEFFS];
    for (i, c) in a.iter_mut().enumerate() {
        *c = u32::try_from(i).expect("bench index");
    }
    for (i, c) in b.iter_mut().enumerate() {
        *c = u32::try_from((i * 3 + 1) % 1_073_750_017).expect("bench coeff");
    }
    let max: Poly = [1_073_750_016; NCOEFFS];
    for (name, x, y) in [("small", &a, &b), ("max", &max, &max)] {
        let mut tn: Vec<f64> = Vec::with_capacity(200);
        let mut tw: Vec<f64> = Vec::with_capacity(200);
        for _ in 0..200 {
            let t0 = Instant::now();
            std::hint::black_box(poly_mul_naive(x, y));
            tn.push(t0.elapsed().as_nanos() as f64);
            let t1 = Instant::now();
            std::hint::black_box(poly_mul_nwc(x, y));
            tw.push(t1.elapsed().as_nanos() as f64);
        }
        let (n0, n5, n9, nx) = stats(tn);
        let (w0, w5, w9, wx) = stats(tw);
        println!("mul/{name}: naive min={n0:.0} p50={n5:.0} p99={n9:.0} max={nx:.0} ns");
        println!("mul/{name}: nwc   min={w0:.0} p50={w5:.0} p99={w9:.0} max={wx:.0} ns");
    }

    // Hash-size table.
    for len in [0usize, 64, 1024, 4096, 8192, 32768] {
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut ts: Vec<f64> = Vec::with_capacity(100);
        for _ in 0..100 {
            let t0 = Instant::now();
            std::hint::black_box(hash(&input));
            ts.push(t0.elapsed().as_nanos() as f64);
        }
        let (a0, a5, a9, ax) = stats(ts);
        println!("hash/{len}: min={a0:.0} p50={a5:.0} p99={a9:.0} max={ax:.0} ns");
    }

    // End-to-end distributions.
    let amat = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t) = sample_witness_for(&amat, &[22; 32]);
    let p0 = prove(&amat, &w, &y, t, &[33; 32]).expect("prove");
    verify(&amat, &y, t, &p0).expect("verify");
    println!("proof_bytes = {}", p0.to_bytes().len());
    let mut tp: Vec<f64> = Vec::with_capacity(200);
    for i in 0..200u32 {
        let mut salt: [u8; 32] = [0x51; 32];
        salt[..4].copy_from_slice(&i.to_le_bytes());
        let t0 = Instant::now();
        std::hint::black_box(prove(&amat, &w, &y, t, &salt).expect("prove"));
        tp.push(t0.elapsed().as_nanos() as f64);
    }
    let mut tv: Vec<f64> = Vec::with_capacity(200);
    for _ in 0..200 {
        let t0 = Instant::now();
        assert!(verify(&amat, &y, t, &p0).is_ok());
        std::hint::black_box(&p0);
        tv.push(t0.elapsed().as_nanos() as f64);
    }
    let (p0n, p05, p09, p0x) = stats(tp);
    let (v0n, v05, v09, v0x) = stats(tv);
    println!("prove   : min={p0n:.0} p50={p05:.0} p99={p09:.0} max={p0x:.0} ns (n=200)");
    println!("verifier: min={v0n:.0} p50={v05:.0} p99={v09:.0} max={v0x:.0} ns (n=200)");
}
