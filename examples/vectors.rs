// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Deterministic proof vectors for the Python differential (`tools/diff_vectors.py`).
//!
//! Prints `Y=`, `T=`, `PROOF=` hex lines for fixed seeds. The Python model
//! recomputes the same inputs and must match byte-for-byte.

use sq_pq::commit::derive_matrix;
use sq_pq::prover::{prove, sample_witness_for};

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn main() {
    let amat = derive_matrix(&[11; 32]).expect("matrix");
    let (w, y, t) = sample_witness_for(&amat, &[22; 32]);
    let mut yflat: [u8; 1024] = [0; 1024];
    for (r, poly) in y.iter().enumerate() {
        for (k, c) in poly.iter().enumerate() {
            yflat[r * 256 + k * 4..r * 256 + k * 4 + 4].copy_from_slice(&c.to_le_bytes());
        }
    }
    println!("Y={}", hex(&yflat));
    println!("T={}", hex(&t.to_le_bytes()));
    for salt in [[33; 32], [44; 32]] {
        let p = prove(&amat, &w, &y, t, &salt).expect("prove");
        println!("PROOF={}", hex(&p.to_bytes()));
    }
}
