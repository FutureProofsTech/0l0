// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! P7 ZK audit: acceptance rate, salt discipline (integration level).
//!
//! Unit-level premises (mask bounds, shift bound, acceptance band) live in
//! `src/prover.rs`; this file measures full-proof behavior across salts.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::many_single_char_names)]

use sq_pq::commit::{derive_matrix, Commitment, MatrixA};
use sq_pq::error::Error;
use sq_pq::params::M_COLS;
use sq_pq::proof::Proof;
use sq_pq::prover::{prove, sample_witness_for};
use sq_pq::ring::Poly;
use sq_pq::verifier::verify;

fn setup() -> (MatrixA, [Poly; M_COLS], Commitment, u32) {
    let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
    (a, w, y, t)
}

fn salt_for(i: u32) -> [u8; 32] {
    let mut s: [u8; 32] = [0xA0; 32];
    s[..4].copy_from_slice(&i.to_le_bytes());
    s
}

/// P7: full-proof success rate across 60 distinct salts.
///
/// Per-round accept ≈ 0.606 with 8 retries gives per-proof failure ≈ 1.3e-3;
/// over 60 proofs expect ≈ 0.08 exhaustions. Asserts `≤ 2` (flake-safe while
/// still catching a broken sampler, which would exhaust nearly always).
#[test]
fn full_proof_success_rate() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let mut exhausted: u32 = 0;
    for i in 0..60 {
        match prove(&a, &w, &y, t, &salt_for(i)) {
            Ok(p) => verify(&a, &y, t, &p).expect("honest verifies"),
            Err(Error::SamplingExhausted) => exhausted += 1,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(exhausted <= 2, "exhausted {exhausted}/60, sampler suspect");
}

/// P7: salt discipline — same salt replays identically (callers MUST rotate),
/// distinct salts diversify the mask commitments.
#[test]
fn salt_discipline() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p1: Proof = prove(&a, &w, &y, t, &salt_for(1)).expect("prove");
    let p2: Proof = prove(&a, &w, &y, t, &salt_for(1)).expect("prove");
    assert_eq!(p1.to_bytes(), p2.to_bytes(), "same salt must replay");
    let p3: Proof = prove(&a, &w, &y, t, &salt_for(2)).expect("prove");
    assert_ne!(
        p1.to_bytes(),
        p3.to_bytes(),
        "distinct salts must diversify"
    );
    verify(&a, &y, t, &p3).expect("verify");
}
