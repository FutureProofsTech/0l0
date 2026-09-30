// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! End-to-end prove/verify (P6 gate) + red-team spot checks.

#![allow(clippy::missing_panics_doc)]
// `(a, w, y, t, p)` is standard lattice notation; renaming would hurt audit.
#![allow(clippy::many_single_char_names)]

use sq_pq::commit::{derive_matrix, Commitment, MatrixA};
use sq_pq::error::Error;
use sq_pq::params::{M_COLS, PROOF_BYTES};
use sq_pq::proof::Proof;
use sq_pq::prover::{prove, sample_witness_for};
use sq_pq::ring::Poly;
use sq_pq::verifier::verify;

fn setup() -> (MatrixA, [Poly; M_COLS], Commitment, u32) {
    let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
    (a, w, y, t)
}

#[test]
fn roundtrip_accepts() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    const { assert!(PROOF_BYTES <= 10_240) };
    assert_eq!(p.to_bytes().len(), PROOF_BYTES);
    verify(&a, &y, t, &p).expect("verify");
}

#[test]
fn roundtrip_second_salt() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[44; 32]).expect("prove");
    verify(&a, &y, t, &p).expect("verify");
}

#[test]
fn prover_refuses_unsatisfied() {
    let (a, w, mut y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    y[0][0] = y[0][0].wrapping_add(1) % 1_073_750_017;
    assert_eq!(
        prove(&a, &w, &y, t, &[33; 32]),
        Err(Error::UnsatisfiedRelation)
    );
}

#[test]
fn wrong_y_rejects() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    let mut y2: Commitment = y;
    y2[1][7] = y2[1][7].wrapping_add(1) % 1_073_750_017;
    assert!(verify(&a, &y2, t, &p).is_err());
}

#[test]
fn wrong_t_rejects() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    assert!(verify(&a, &y, t.wrapping_add(1) % 1_073_750_017, &p).is_err());
}

#[test]
fn tampered_response_rejects() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let mut p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    // Flip a byte inside round-0 `z` (offset 1 + 1024 + 100).
    p.body[1 + 1024 + 100] ^= 1;
    assert!(verify(&a, &y, t, &p).is_err());
}

#[test]
fn tampered_commitment_rejects() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let mut p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    p.body[10] ^= 0xFF;
    assert!(verify(&a, &y, t, &p).is_err());
}

#[test]
fn bitflip_sweep_rejects() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    let raw: [u8; PROOF_BYTES] = p.to_bytes();
    // 65 sampled positions across all regions (full sweep is a nightly job).
    let mut checked: u32 = 0;
    let mut i: usize = 0;
    while i < PROOF_BYTES {
        let mut tmp: [u8; PROOF_BYTES] = raw;
        tmp[i] ^= 1;
        // Position 0 is the version byte: any flip must fail at parse.
        let res: Result<(), Error> = Proof::from_bytes(&tmp)
            .map(|pp| verify(&a, &y, t, &pp))
            .and_then(|r| r);
        assert!(res.is_err(), "bitflip at {i} must reject");
        checked += 1;
        i += 71;
    }
    assert!(checked >= 60);
}
