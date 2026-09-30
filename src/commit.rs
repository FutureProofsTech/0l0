// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Ajtai commitment + binary gadget decomposition.
//!
//! The public matrix derives deterministically from a 32-byte seed via the
//! BLAKE3 XOF (uniform mod `Q` by `u32` rejection sampling, fixed bounds).
//! Commitments are naive/NWC matrix products. The binary gadget turns the
//! exact packing claim into short opening material for the P5 follow-up;
//! v0.1 already uses it in red-team gadget roundtrips.

use crate::error::{Error, Result};
use crate::hash::xof_into;
use crate::params::{D, M_COLS, N_ROWS, Q};
use crate::ring::{Poly, NCOEFFS};

/// Commitment matrix: `N_ROWS × M_COLS` polynomials over `R_q`.
pub type MatrixA = [[Poly; M_COLS]; N_ROWS];

/// Commitment: `N_ROWS` ring elements.
pub type Commitment = [Poly; N_ROWS];

/// Domain tag for matrix expansion (distinct from transcript tags).
pub const TAG_MATRIX: u8 = 0x41;

/// Expand one uniform `< Q` coefficient from the XOF stream.
///
/// Reads 4 bytes as `u32::from_le_bytes` and rejects values `>= Q`,
/// advancing a fixed-stride cursor. Rejection is over public randomness
/// (no secret-dependent timing on witness data).
fn stream_coeff(stream: &[u8], cursor: &mut usize) -> Option<u32> {
    if *cursor + 4 > stream.len() {
        return None;
    }
    let v: u32 = u32::from_le_bytes([
        stream[*cursor],
        stream[*cursor + 1],
        stream[*cursor + 2],
        stream[*cursor + 3],
    ]);
    *cursor += 4;
    if v < Q {
        Some(v)
    } else {
        None
    }
}

/// Derive the public matrix deterministically from `seed`.
///
/// Each of the 32 polynomials expands independently: `XOF(seed ‖ TAG ‖ r ‖
/// c ‖ attempt)` fills a 2048-byte stream (the XOF cap), from which 64
/// accepted `< Q` coefficients are rejection-sampled (acceptance
/// `Q/2^32 ≈ 0.25`; expected ≈128 accepted per 512-candidate stream,
/// shortfall ≈7e-13 per poly). Counter-suffixed retries make total
/// derivation failure cryptographically negligible. Per-poly domains keep
/// frames small and stack-only.
///
/// # Errors
/// * [`Error::InvalidParams`] on XOF failure or exhausted retries
///   (unreachable for the frozen sizes).
pub fn derive_matrix(seed: &[u8; 32]) -> Result<MatrixA> {
    let mut a: MatrixA = [[[0; NCOEFFS]; M_COLS]; N_ROWS];
    for r in 0..N_ROWS {
        for c in 0..M_COLS {
            let mut done: bool = false;
            let mut attempt: u8 = 0;
            while !done && attempt < 8 {
                let mut input: [u8; 36] = [0; 36];
                input[..32].copy_from_slice(seed);
                input[32] = TAG_MATRIX;
                input[33] = r as u8;
                input[34] = c as u8;
                input[35] = attempt;
                let mut stream: [u8; 2048] = [0; 2048];
                xof_into(&input, TAG_MATRIX, &mut stream)?;
                let mut cursor: usize = 0;
                let mut k: usize = 0;
                while k < D {
                    match stream_coeff(&stream, &mut cursor) {
                        Some(v) => {
                            a[r][c][k] = v;
                            k += 1;
                        }
                        None => {
                            if cursor + 4 > stream.len() {
                                break;
                            }
                        }
                    }
                }
                done = k >= D;
                attempt += 1;
            }
            if !done {
                return Err(Error::InvalidParams);
            }
        }
    }
    Ok(a)
}

/// Commit `t = A·w` (fast path — see [`commit_fast`]; bitwise identical).
#[must_use]
pub fn commit(a: &MatrixA, w: &[Poly; M_COLS]) -> Commitment {
    commit_fast(a, w)
}

/// Twisted NTT of a matrix, computed once per prove/verify call (S1 hoist).
///
/// Type is an anonymous nested array (no new public type): twisted-NTT
/// polys in `[row][col][coeff]` order. Values identical to twisting +
/// [`ntt_forward`][crate::ring::ntt_forward] per poly on demand.
pub(crate) fn twisted_ntt_matrix(a: &MatrixA) -> [[[u32; NCOEFFS]; M_COLS]; N_ROWS] {
    use crate::ring::{mul_mod_u32, ntt_forward, PSI_POW};
    let mut antt: [[[u32; NCOEFFS]; M_COLS]; N_ROWS] = [[[0; NCOEFFS]; M_COLS]; N_ROWS];
    for (r, row) in a.iter().enumerate() {
        for (c, poly) in row.iter().enumerate() {
            let mut tw: Poly = [0; NCOEFFS];
            for (j, v) in poly.iter().enumerate() {
                tw[j] = mul_mod_u32(*v, PSI_POW[j]);
            }
            antt[r][c] = ntt_forward(&tw);
        }
    }
    antt
}

/// Matrix commitment from a precomputed twisted-NTT matrix (same values as
/// [`commit`]; saves re-transforming `A` on every call within one
/// prove/verify invocation).
#[must_use]
pub(crate) fn commit_precomputed(
    antt: &[[[u32; NCOEFFS]; M_COLS]; N_ROWS],
    w: &[Poly; M_COLS],
) -> Commitment {
    use crate::ring::{mul_mod_u32, ntt_forward, PSI_POW};
    let mut wntt: [[u32; NCOEFFS]; M_COLS] = [[0; NCOEFFS]; M_COLS];
    for (c, poly) in w.iter().enumerate() {
        let mut tw: Poly = [0; NCOEFFS];
        for (j, v) in poly.iter().enumerate() {
            tw[j] = mul_mod_u32(*v, PSI_POW[j]);
        }
        wntt[c] = ntt_forward(&tw);
    }
    accumulate_rows(antt, &wntt)
}

/// Pointwise-accumulate `Σ_c antt[r][c]·wntt[c]` per row + INTT + untwist.
fn accumulate_rows(
    antt: &[[[u32; NCOEFFS]; M_COLS]; N_ROWS],
    wntt: &[[u32; NCOEFFS]; M_COLS],
) -> Commitment {
    use crate::ring::{mul_mod_u32, ntt_inverse, PSI_INV_POW};
    let mut t: Commitment = [[0; NCOEFFS]; N_ROWS];
    for r in 0..N_ROWS {
        let mut acc: [u64; NCOEFFS] = [0; NCOEFFS];
        for c in 0..M_COLS {
            for j in 0..NCOEFFS {
                acc[j] += u64::from(antt[r][c][j]) * u64::from(wntt[c][j]);
            }
        }
        let mut cw: Poly = [0; NCOEFFS];
        for (j, v) in acc.iter().enumerate() {
            cw[j] = (v % u64::from(Q)) as u32;
        }
        let mut row: Poly = ntt_inverse(&cw);
        for (j, v) in row.iter_mut().enumerate() {
            *v = mul_mod_u32(*v, PSI_INV_POW[j]);
        }
        t[r] = row;
    }
    t
}
/// NTT-domain matrix commitment (fast path, same values as naive).
///
/// Single-call form: precomputes `NTT(twist(A))` internally (44 transforms
/// vs 96 for the per-product path). Callers that commit repeatedly under
/// one `A` (prove/verify) hoist via the crate-internal twisted-matrix +
/// precomputed-commit helpers instead. Equivalence with the naive ground
/// truth is proven by the `commit_fast_matches_naive` differential test.
#[must_use]
pub fn commit_fast(a: &MatrixA, w: &[Poly; M_COLS]) -> Commitment {
    let antt: [[[u32; NCOEFFS]; M_COLS]; N_ROWS] = twisted_ntt_matrix(a);
    commit_precomputed(&antt, w)
}

/// Naive single-row commitment (ground-truth reference for tests).
///
/// Test-only: release relies on [`commit_fast`] with identical values,
/// proven by the `commit_fast_matches_naive` differential test (which also
/// runs in release CI via `cargo test --release`).
#[cfg(test)]
pub(crate) fn commit_naive_row(a: &MatrixA, w: &[Poly; M_COLS], r: usize) -> Poly {
    use crate::ring::{poly_add, poly_mul_naive};
    let mut acc: Poly = [0; NCOEFFS];
    for c in 0..M_COLS {
        acc = poly_add(&acc, &poly_mul_naive(&a[r][c], &w[c]));
    }
    acc
}

/// Binary gadget length: `Q = 2^30 + 2^13 + 1` needs bits `0..=30`.
pub const GADGET_LEN: usize = 31;

/// Gadget vector `g[i] = 2^i mod Q` (compile-time).
pub const GADGET: [u32; GADGET_LEN] = {
    let mut g: [u32; GADGET_LEN] = [0; GADGET_LEN];
    let mut p: u32 = 1;
    let mut i: usize = 0;
    while i < GADGET_LEN {
        g[i] = p;
        // `p < 2^30`, doubling stays `< 2^31 < 2·Q`: subtract once if needed.
        let doubled: u32 = p << 1;
        p = if doubled >= Q { doubled - Q } else { doubled };
        i += 1;
    }
    g
};

/// Binary decomposition of `v < Q` into 30 bits (LSB first).
#[must_use]
pub fn decomp_coeff(v: u32) -> [u8; GADGET_LEN] {
    let mut out: [u8; GADGET_LEN] = [0; GADGET_LEN];
    for i in 0..GADGET_LEN {
        out[i] = ((v >> i) & 1) as u8;
    }
    out
}

/// Recompose: `Σ bits[i]·2^i mod Q` (inverts [`decomp_coeff`] for `< Q`).
#[must_use]
pub fn compose_coeff(bits: &[u8; GADGET_LEN]) -> u32 {
    let mut acc: u64 = 0;
    for i in 0..GADGET_LEN {
        acc += u64::from(bits[i]) * u64::from(GADGET[i]);
    }
    // `acc < 2^36`: lossless by construction.
    (acc % u64::from(Q)) as u32
}

/// Decompose a polynomial coefficient-wise (bits packed per coefficient).
#[must_use]
pub fn decomp_poly(p: &Poly) -> [[u8; GADGET_LEN]; NCOEFFS] {
    let mut out: [[u8; GADGET_LEN]; NCOEFFS] = [[0; GADGET_LEN]; NCOEFFS];
    for (k, row) in out.iter_mut().enumerate() {
        *row = decomp_coeff(p[k]);
    }
    out
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::{
        commit, commit_fast, commit_naive_row, compose_coeff, decomp_coeff, derive_matrix,
    };
    use super::{GADGET_LEN, M_COLS, N_ROWS};
    use crate::params::Q;
    use crate::ring::{Poly, NCOEFFS};

    #[test]
    fn matrix_deterministic_and_reduced() {
        let a1: super::MatrixA = derive_matrix(&[3; 32]).expect("derive");
        let a2: super::MatrixA = derive_matrix(&[3; 32]).expect("derive");
        assert_eq!(a1, a2);
        let a3: super::MatrixA = derive_matrix(&[4; 32]).expect("derive");
        assert_ne!(a1, a3);
        for row in &a1 {
            for poly in row {
                for c in poly {
                    assert!(*c < Q);
                }
            }
        }
    }

    #[test]
    fn commit_zero_and_linearity() {
        use crate::ring::{Poly, NCOEFFS};
        let a: super::MatrixA = derive_matrix(&[9; 32]).expect("derive");
        let z: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        let t: super::Commitment = commit(&a, &z);
        assert_eq!(t, [[0; NCOEFFS]; crate::params::N_ROWS]);
        // Linearity: commit(a, u+v) = commit(a,u) + commit(a,v).
        let mut u: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        let mut v: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        u[0][0] = 1;
        u[1][5] = Q - 1;
        v[2][3] = 7;
        let mut s: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        for i in 0..crate::params::M_COLS {
            for k in 0..NCOEFFS {
                s[i][k] = (u[i][k] + v[i][k]) % Q;
            }
        }
        let (tu, tv, ts): (super::Commitment, super::Commitment, super::Commitment) =
            (commit(&a, &u), commit(&a, &v), commit(&a, &s));
        for r in 0..crate::params::N_ROWS {
            for k in 0..NCOEFFS {
                assert_eq!((tu[r][k] + tv[r][k]) % Q, ts[r][k]);
            }
        }
    }

    #[test]
    fn gadget_roundtrip() {
        assert_eq!(GADGET_LEN, 31);
        for v in [0, 1, 2, 7, 255, Q - 1, Q / 2, 123_456] {
            assert_eq!(compose_coeff(&decomp_coeff(v)), v, "v={v}");
        }
        // Bits are binary and short.
        let d: [u8; GADGET_LEN] = decomp_coeff(Q - 1);
        for b in &d {
            assert!(*b <= 1);
        }
    }

    /// Fast NTT-domain commitment equals the naive ground truth bitwise
    /// (random + edge inputs, incl. max coefficients).
    #[test]
    fn commit_fast_matches_naive() {
        let a: super::MatrixA = derive_matrix(&[17; 32]).expect("derive");
        let mut s: u64 = 0x00C0_FFEE;
        let mut rnd = || {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z: u64 = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for _ in 0..8 {
            let mut w: [Poly; M_COLS] = [[0; NCOEFFS]; M_COLS];
            for poly in &mut w {
                for c in poly.iter_mut() {
                    *c = u32::try_from(rnd() % u64::from(Q)).expect("mod q");
                }
            }
            let fast: super::Commitment = commit_fast(&a, &w);
            for r in 0..N_ROWS {
                assert_eq!(fast[r], commit_naive_row(&a, &w, r));
            }
            assert_eq!(commit(&a, &w), fast);
        }
        let max: [Poly; M_COLS] = [[Q - 1; NCOEFFS]; M_COLS];
        for r in 0..N_ROWS {
            assert_eq!(commit_fast(&a, &max)[r], commit_naive_row(&a, &max, r));
        }
    }
}
