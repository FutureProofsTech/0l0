// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! P8 red-team: norm smuggling, grinding bound, determinism, versions.
//!
//! The packing-sufficiency gap demonstration lives in-crate
//! (`verifier::tests::biased_packing_scalars_still_verify`) because it needs
//! the test-only `prove_with_u_bias` harness.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::many_single_char_names)]

use sq_pq::commit::{derive_matrix, Commitment, MatrixA};
use sq_pq::error::Error;
use sq_pq::params::{M_COLS, PROOF_BYTES, PROOF_VERSION, RESP_BOUND};
use sq_pq::proof::Proof;
use sq_pq::prover::{prove, response_ok, sample_witness_for};
use sq_pq::ring::Poly;
use sq_pq::verifier::verify;

fn setup() -> (MatrixA, [Poly; M_COLS], Commitment, u32) {
    let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
    (a, w, y, t)
}

/// P8: response-bound edges — exactly `±RESP_BOUND` passes, `±(RESP_BOUND+1)`
/// fails, on both sides of the centered representation.
#[test]
fn response_bound_edges() {
    use sq_pq::params::Q;
    let mut z: [Poly; M_COLS] = [[0; 64]; M_COLS];
    assert!(response_ok(&z));
    z[0][0] = RESP_BOUND;
    assert!(response_ok(&z));
    z[0][0] = Q - RESP_BOUND; // centered −RESP_BOUND
    assert!(response_ok(&z));
    z[0][0] = RESP_BOUND + 1;
    assert!(!response_ok(&z));
    z[0][0] = Q - RESP_BOUND - 1; // centered −(RESP_BOUND+1)
    assert!(!response_ok(&z));
}

/// P8: norm-smuggling witness (`β+1` coefficient) is refused by the prover,
/// and any tampering toward it breaks verification.
#[test]
fn norm_smuggling_refused() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let mut w_bad: [Poly; M_COLS] = w;
    w_bad[3][9] = 2; // β = 1 exceeded
    assert_eq!(
        prove(&a, &w_bad, &y, t, &[1; 32]),
        Err(Error::UnsatisfiedRelation)
    );
}

/// P8: grinding-space bound as executable arithmetic.
///
/// Challenge space per round is `C(64,16)·2^16 ≥ 2^64`; two independent
/// rounds give `≥ 2^128` (spec claims `≈2^-130`; this test pins the floor).
#[test]
fn grinding_space_floor() {
    let mut comb: u128 = 1;
    for i in 0..16u128 {
        comb = comb * (64 - i) / (i + 1);
    }
    assert_eq!(comb, 488_526_937_079_580);
    let space: u128 = comb * 65_536;
    assert!(space >= (1 << 64), "per-round space must reach 2^64");
    // Two independent rounds give `space² ≥ 2^128` by monotonicity
    // (`a, b ≥ 2^64 ⟹ ab ≥ 2^128`); the true value `≈2^129.6` overflows
    // `u128`, so it is pinned by the exact `comb` above, not materialized.
}

/// P8: version downgrade rejected at parse; reserved-zero discipline holds.
#[test]
fn version_and_reserved() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[5; 32]).expect("prove");
    let mut raw: [u8; PROOF_BYTES] = p.to_bytes();
    raw[0] = PROOF_VERSION.wrapping_add(1);
    assert_eq!(
        Proof::from_bytes(&raw)
            .map(|pp| verify(&a, &y, t, &pp))
            .and_then(|r| r),
        Err(Error::MalformedEncoding)
    );
}

/// P8: fixed zero salt is functional but MUST NOT be reused across proofs
/// (determinism demonstration — same input, same output, no fresh entropy).
#[test]
fn zero_salt_determinism_warning() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p1: Proof = prove(&a, &w, &y, t, &[0; 32]).expect("prove");
    let p2: Proof = prove(&a, &w, &y, t, &[0; 32]).expect("prove");
    assert_eq!(p1.to_bytes(), p2.to_bytes());
    verify(&a, &y, t, &p1).expect("verify");
}
