// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! In-tree deterministic fuzzer (Q7): structured mutations, fixed seeds.
//!
//! Complements `cargo-fuzz` (which found a harness bug in minutes): this
//! suite runs in plain `cargo test` with reproducible corpora. Properties:
//! no panics on any input; mutated honest proofs reject; transcript API is
//! total on its documented domain and deterministic.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::many_single_char_names)]

use sq_pq::commit::{derive_matrix, Commitment, MatrixA};
use sq_pq::params::{M_COLS, PROOF_BYTES};
use sq_pq::proof::Proof;
use sq_pq::prover::{prove, sample_witness_for};
use sq_pq::ring::Poly;
use sq_pq::transcript::Transcript;
use sq_pq::verifier::verify;

const fn splitmix(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z: u64 = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn setup() -> (MatrixA, [Poly; M_COLS], Commitment, u32, Proof) {
    let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    (a, w, y, t, p)
}

/// N mutated proofs (bitflips + region wipes) must never panic and must
/// reject (a mutated honest proof is invalid with overwhelming probability;
/// the count below guards the fuzzer actually exercises rejections).
#[test]
fn fuzz_mutated_proofs_reject() {
    let (a, _w, y, t, p): (MatrixA, [Poly; M_COLS], Commitment, u32, Proof) = setup();
    let raw: [u8; PROOF_BYTES] = p.to_bytes();
    let mut s: u64 = 0xF021;
    let mut rejected: u32 = 0;
    let mut noop: u32 = 0;
    for i in 0..2000 {
        let mut tmp: [u8; PROOF_BYTES] = raw;
        let kind: u64 = splitmix(&mut s) % 3;
        if kind == 0 {
            // 1–8 random bitflips.
            let n: usize = 1 + usize::try_from(splitmix(&mut s) % 8).expect("bit");
            for _ in 0..n {
                let pos: usize =
                    usize::try_from(splitmix(&mut s) % PROOF_BYTES as u64).expect("pos");
                let bit: u8 = 1 << (splitmix(&mut s) % 8);
                tmp[pos] ^= bit;
            }
        } else if kind == 1 {
            // Random block wipe (64 B window).
            let pos: usize =
                usize::try_from(splitmix(&mut s) % (PROOF_BYTES - 64) as u64).expect("pos");
            tmp[pos..pos + 64].copy_from_slice(&[0; 64]);
        } else {
            // Fully random body (version byte kept valid to reach verify).
            for b in tmp.iter_mut().skip(1) {
                *b = u8::try_from(splitmix(&mut s) % 256).expect("byte");
            }
            let _ = i;
        }
        let res = Proof::from_bytes(&tmp)
            .map(|pp| verify(&a, &y, t, &pp))
            .and_then(|r| r);
        if tmp == raw {
            // No-op mutation (e.g., zero-wipe fully inside the reserved-zero
            // regions): the proof is unchanged and MUST still accept.
            assert!(res.is_ok(), "no-op mutation must still verify");
            noop += 1;
        } else if res.is_err() {
            rejected += 1;
        } else if std::env::var("FUZZ_DEBUG").is_ok() {
            eprintln!("ACCEPT kind={kind} iter={i}");
        }
    }
    assert_eq!(rejected + noop, 2000, "every case accounted");
    assert!(
        noop <= 60,
        "fuzzer must mostly hit checked bytes ({noop} no-ops)"
    );
    assert!(rejected >= 1940, "mutations must overwhelmingly reject");
}

/// Fully random arrays (arbitrary versions) parse-or-reject without panic.
#[test]
fn fuzz_random_arrays_no_panic() {
    let (a, _w, y, t, _p): (MatrixA, [Poly; M_COLS], Commitment, u32, Proof) = setup();
    let mut s: u64 = 0xBEEF;
    for _ in 0..500 {
        let mut raw: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        for b in &mut raw {
            *b = u8::try_from(splitmix(&mut s) % 256).expect("byte");
        }
        let _ = Proof::from_bytes(&raw).map(|pp| verify(&a, &y, t, &pp));
    }
}

/// Transcript fuzz: arbitrary label/data lengths (incl. over-limit) never
/// panic; in-domain behavior deterministic.
#[test]
fn fuzz_transcript_total() {
    let mut s: u64 = 0xA11CE;
    for _ in 0..500 {
        let ll: usize = (splitmix(&mut s) % 80) as usize;
        let dl: usize = (splitmix(&mut s) % 2200) as usize;
        let mut label: [u8; 80] = [0; 80];
        let mut data: [u8; 2200] = [0; 2200];
        for b in &mut label[..ll] {
            *b = u8::try_from(splitmix(&mut s) % 256).expect("byte");
        }
        for b in &mut data[..dl] {
            *b = u8::try_from(splitmix(&mut s) % 256).expect("byte");
        }
        let mut t1: Transcript = Transcript::new(b"sq-pq/v0.1/R*");
        let mut t2: Transcript = Transcript::new(b"sq-pq/v0.1/R*");
        let r1: Result<(), sq_pq::error::Error> = t1.absorb(&label[..ll], &data[..dl]);
        let r2: Result<(), sq_pq::error::Error> = t2.absorb(&label[..ll], &data[..dl]);
        assert_eq!(r1.is_ok(), r2.is_ok());
        assert_eq!(r1.is_ok(), ll <= 64 && dl <= 2048);
        if r1.is_ok() {
            let mut o1: [u8; 32] = [0; 32];
            let mut o2: [u8; 32] = [0; 32];
            t1.squeeze(0x46, &mut o1).expect("squeeze");
            t2.squeeze(0x46, &mut o2).expect("squeeze");
            assert_eq!(o1, o2);
        }
    }
}
