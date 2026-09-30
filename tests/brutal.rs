// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! BRUTAL red-team suite: every feasible attack vector, measured.
//!
//! - Exhaustive single-bitflip sweep (all 4577 bytes × all 8 bits).
//!
//! - Random two-bit pairs, round-block swaps, cross-proof splices.
//! - 20k-trial direct-grinding game on random wire bytes.
//! - 200-salt exhaustion census, sparsity classes, mask diversity.
//! - Decode edges, framing lengths, API limits, transcript collisions.
//! - Zero-witness edge.
//!
//! All results are recorded in `docs/redteam-log.md` (measured, dated).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::many_single_char_names)]

use sq_pq::commit::{derive_matrix, Commitment, MatrixA};
use sq_pq::error::Error;
use sq_pq::params::{M_COLS, PROOF_BYTES, PROOF_VERSION, Q};
use sq_pq::proof::{Proof, CHAL_OFF, PACK_OFF};
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

fn setup() -> (MatrixA, [Poly; M_COLS], Commitment, u32) {
    let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
    (a, w, y, t)
}

fn check(raw: &[u8; PROOF_BYTES], a: &MatrixA, y: &Commitment, t: u32) -> Result<(), Error> {
    Proof::from_bytes(raw)
        .map(|p| verify(a, y, t, &p))
        .and_then(|r| r)
}

/// B1: exhaustive single-bitflip sweep — all 4577 positions × all 8 bits
/// (36,616 mutants), every one must reject.
#[test]
fn b1_exhaustive_single_bitflip() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    let raw: [u8; PROOF_BYTES] = p.to_bytes();
    let mut n: u32 = 0;
    for i in 0..PROOF_BYTES {
        for b in 0..8u32 {
            let mut tmp: [u8; PROOF_BYTES] = raw;
            tmp[i] ^= 1 << b;
            assert!(check(&tmp, &a, &y, t).is_err(), "flip survived at {i}:{b}");
            n += 1;
        }
    }
    assert_eq!(n, 4577 * 8, "sweep must cover every bit");
    eprintln!("B1 exhaustive bitflip: {n}/{n} rejected");
}

/// B2: 5000 random two-bit pairs (distinct positions), all must reject.
#[test]
fn b2_random_two_bit_pairs() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let raw: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[33; 32]).expect("prove").to_bytes();
    let mut s: u64 = 0x2B17;
    for _ in 0..5000 {
        let i: usize = usize::try_from(splitmix(&mut s) % PROOF_BYTES as u64).expect("index");
        let mut j: usize = usize::try_from(splitmix(&mut s) % PROOF_BYTES as u64).expect("index");
        while j == i {
            j = usize::try_from(splitmix(&mut s) % PROOF_BYTES as u64).expect("index");
        }
        let mut tmp: [u8; PROOF_BYTES] = raw;
        tmp[i] ^= 1 << usize::try_from(splitmix(&mut s) % 8).expect("bit");
        tmp[j] ^= 1 << usize::try_from(splitmix(&mut s) % 8).expect("bit");
        assert!(check(&tmp, &a, &y, t).is_err(), "pair survived at {i},{j}");
    }
}

/// B3: round-block swap (round 0 ↔ round 1 bodies) must reject — the round
/// index is bound in the challenge.
#[test]
fn b3_round_block_swap() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: Proof = prove(&a, &w, &y, t, &[33; 32]).expect("prove");
    let mut tmp: [u8; PROOF_BYTES] = p.to_bytes();
    // Round blocks: body[0..2112] ↔ body[2112..4224] (wire offset +1).
    for i in 0..2112 {
        tmp.swap(1 + i, 1 + 2112 + i);
    }
    assert!(check(&tmp, &a, &y, t).is_err());
}

/// B4: cross-proof splice — `t1_0` from a second proof (same `y`, other
/// salt) transplanted in must reject in both directions.
#[test]
fn b4_cross_proof_splice() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p1: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[33; 32]).expect("prove").to_bytes();
    let p2: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[44; 32]).expect("prove").to_bytes();
    assert_ne!(p1, p2);
    for (dst, src) in [(&p1, &p2), (&p2, &p1)] {
        let mut tmp: [u8; PROOF_BYTES] = *dst;
        tmp[1..=1024].copy_from_slice(&src[1..=1024]);
        assert!(check(&tmp, &a, &y, t).is_err(), "spliced t1 accepted");
    }
}

/// B5: direct-grinding game — 20,000 fully random wire proofs (valid
/// version byte, half with zeroed reserved regions so they reach the
/// linear equations). Expectation: 0 accepts (each trial faces
/// `q^-256`-scale equation odds).
#[test]
fn b5_grinding_random_wire() {
    let (a, _w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let mut s: u64 = 0x9712;
    let mut accepts: u32 = 0;
    for i in 0..20000 {
        let mut raw: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        for b in &mut raw {
            *b = u8::try_from(splitmix(&mut s) % 256).expect("byte");
        }
        raw[0] = PROOF_VERSION;
        if i % 2 == 0 {
            // Zero the reserved regions to force evaluation of every check.
            raw[1 + PACK_OFF + 16..=CHAL_OFF].copy_from_slice(&[0; 272]);
            raw[1 + CHAL_OFF + 32..PROOF_BYTES].copy_from_slice(&[0; 32]);
        }
        if check(&raw, &a, &y, t).is_ok() {
            accepts += 1;
        }
    }
    assert_eq!(accepts, 0, "random forgery accepted!");
    eprintln!("B5 grinding: {accepts}/20000 accepts");
}

/// B6: 200-salt exhaustion census — honest proving must essentially never
/// hit `SamplingExhausted` (per-proof fail ≈ 1.3e-3 → expect ~0.26).
#[test]
fn b6_census_200_salts() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let mut exhausted: u32 = 0;
    for i in 0..200u32 {
        let mut salt: [u8; 32] = [0xC0; 32];
        salt[..4].copy_from_slice(&i.to_le_bytes());
        match prove(&a, &w, &y, t, &salt) {
            Ok(p) => verify(&a, &y, t, &p).expect("honest verifies"),
            Err(Error::SamplingExhausted) => exhausted += 1,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert!(exhausted <= 2, "exhausted {exhausted}/200, sampler suspect");
    eprintln!("B6 census: exhausted {exhausted}/200");
}

/// B7: sparsity classes — zero witness (sparsest possible, valid statement)
/// and dense witness both prove at full rate; acceptance must not depend
/// on witness density (timing-channel R1 magnitude check).
#[test]
fn b7_sparsity_classes() {
    let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
    let w0: [Poly; M_COLS] = [[0; 64]; M_COLS];
    let y0: Commitment = [[0; 64]; 4];
    assert!(sq_pq::prover::check_relation(&a, &w0, &y0, 0));
    let (wd, yd, td): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
    for (w, y, t, tag) in [(w0, y0, 0, "sparse"), (wd, yd, td, "dense")] {
        let mut exhausted: u32 = 0;
        for i in 0..40u32 {
            let mut salt: [u8; 32] = [0xD0; 32];
            salt[..4].copy_from_slice(&i.to_le_bytes());
            match prove(&a, &w, &y, t, &salt) {
                Ok(p) => verify(&a, &y, t, &p).expect("verifies"),
                Err(Error::SamplingExhausted) => exhausted += 1,
                Err(e) => panic!("{tag}: unexpected {e:?}"),
            }
        }
        assert!(exhausted <= 2, "{tag}: exhausted {exhausted}/40");
        eprintln!("B7 {tag}: exhausted {exhausted}/40");
    }
}

/// B8: mask diversity — two salts must differ in most `z` bytes (masks are
/// fresh uniform; identical responses would signal entropy failure).
#[test]
fn b8_mask_diversity() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p1: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[33; 32]).expect("prove").to_bytes();
    let p2: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[44; 32]).expect("prove").to_bytes();
    // Round-0 `z` region: body[1024..2112] → wire[1025..2113].
    let diff: usize = p1[1025..2113]
        .iter()
        .zip(p2[1025..2113].iter())
        .filter(|(x, y)| x != y)
        .count();
    assert!(
        diff > 512,
        "masks suspiciously similar ({diff}/1088 bytes differ)"
    );
    eprintln!("B8 mask diversity: {diff}/1088 z-bytes differ");
}

/// B9: decode edges — non-canonical `t1` coefficient (`= Q`) and maximal
/// pack scalar (`0xFFFFFFFF`) must fail at parse/verify with
/// `MalformedEncoding`.
#[test]
fn b9_decode_edges() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let p: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[33; 32]).expect("prove").to_bytes();
    // `t1[0][0] = Q` (LE bytes 01 34 00 40).
    let mut t1bad: [u8; PROOF_BYTES] = p;
    t1bad[1..5].copy_from_slice(&Q.to_le_bytes());
    assert_eq!(
        Proof::from_bytes(&t1bad)
            .map(|pp| verify(&a, &y, t, &pp))
            .and_then(|r| r),
        Err(Error::MalformedEncoding)
    );
    // Pack scalar `u0 = 0xFFFFFFFF ≥ Q`.
    let mut ubad: [u8; PROOF_BYTES] = p;
    ubad[1 + PACK_OFF..1 + PACK_OFF + 4].copy_from_slice(&[0xFF; 4]);
    assert_eq!(
        Proof::from_bytes(&ubad)
            .map(|pp| verify(&a, &y, t, &pp))
            .and_then(|r| r),
        Err(Error::MalformedEncoding)
    );
}

/// B10: framing lengths — 0, 4576, 4578, 6497 bytes rejected; exact 4577
/// with valid content accepted.
#[test]
fn b10_framing_lengths() {
    let (a, w, y, t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let raw: [u8; PROOF_BYTES] = prove(&a, &w, &y, t, &[33; 32]).expect("prove").to_bytes();
    assert!(Proof::from_slice(&[]).is_err());
    assert!(Proof::from_slice(&raw[..4576]).is_err());
    assert!(Proof::from_slice(&raw).is_ok());
    let mut long: Vec<u8> = raw.to_vec();
    long.push(0);
    assert!(Proof::from_slice(&long).is_err());
    assert!(Proof::from_slice(&[0u8; 6497]).is_err());
}

/// B11: API limits fail closed — oversize hash/XOF/transcript inputs.
#[test]
fn b11_api_limits() {
    assert_eq!(
        sq_pq::hash::try_hash(&vec![0u8; 32769]),
        Err(Error::InputTooLong)
    );
    let mut out: [u8; 2049] = [0; 2049];
    assert_eq!(
        sq_pq::hash::xof_into(b"x", 0, &mut out),
        Err(Error::InputTooLong)
    );
    let mut tr: Transcript = Transcript::new(b"t");
    assert_eq!(tr.absorb(&[0u8; 65], b"x"), Err(Error::TranscriptError));
    assert_eq!(tr.absorb(b"x", &[0u8; 2049]), Err(Error::TranscriptError));
}

/// B12: matrix seeds — all-zero and all-FF seeds derive fine,
/// deterministically, fully reduced, and distinctly.
#[test]
fn b12_matrix_seed_edges() {
    let z1 = derive_matrix(&[0; 32]).expect("zero seed");
    let z2 = derive_matrix(&[0; 32]).expect("zero seed");
    let f = derive_matrix(&[0xFF; 32]).expect("ff seed");
    assert_eq!(z1, z2);
    assert_ne!(z1, f);
    for m in [&z1, &f] {
        for row in m {
            for poly in row {
                for c in poly {
                    assert!(*c < Q);
                }
            }
        }
    }
}

/// B13: transcript framing — ("ab","c") vs ("a","bc") diverge; domain tags
/// separate identical inputs.
#[test]
fn b13_transcript_framing() {
    let mut a1: Transcript = Transcript::new(b"t");
    let mut a2: Transcript = Transcript::new(b"t");
    a1.absorb(b"ab", b"c").expect("absorb");
    a2.absorb(b"a", b"bc").expect("absorb");
    assert_ne!(a1.state(), a2.state());
    let mut t1: Transcript = Transcript::new(b"t");
    let mut t2: Transcript = Transcript::new(b"t");
    t1.absorb(b"x", b"data").expect("absorb");
    t2.absorb(b"x", b"data").expect("absorb");
    let mut o1: [u8; 32] = [0; 32];
    let mut o2: [u8; 32] = [0; 32];
    t1.squeeze(0x50, &mut o1).expect("squeeze");
    t2.squeeze(0x42, &mut o2).expect("squeeze");
    assert_ne!(o1, o2);
}

/// B14: zero witness edge — `(w=0, y=0, t=0)` is a valid statement and
/// proves/verifies (masks still diversify).
#[test]
fn b14_zero_witness() {
    let (a, _w, _y, _t): (MatrixA, [Poly; M_COLS], Commitment, u32) = setup();
    let w: [Poly; M_COLS] = [[0; 64]; M_COLS];
    let y: Commitment = [[0; 64]; 4];
    let p1: Proof = prove(&a, &w, &y, 0, &[1; 32]).expect("prove");
    let p2: Proof = prove(&a, &w, &y, 0, &[2; 32]).expect("prove");
    verify(&a, &y, 0, &p1).expect("verify");
    verify(&a, &y, 0, &p2).expect("verify");
    assert_ne!(p1.to_bytes(), p2.to_bytes());
}
