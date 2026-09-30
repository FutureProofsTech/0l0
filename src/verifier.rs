// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Verifier: linear equations + response bounds + transcript binding.
//!
//! Per round `j`, with challenge `c_j` re-derived from the transcript over
//! the proof's own `(t1_j, u_j)` plus all public inputs (including the
//! packing scalar `t`), checks:
//! 1. `A·z_j = t1_j + c_j⋆y` (NWC products, exact `u64` arithmetic).
//! 2. `‖z_j‖_∞ ≤ RESP_BOUND` (centered).
//! 3. Decoding canonicality (`< Q` coefficients, reserved zeros zero).
//!
//! Packing scalars `(u_j, v_j)` are transcript-bound (they feed the
//! challenge) and range-checked; the packing-sufficiency aggregation (an
//! equation checkable without `w`) is the labeled P5-follow-up — see
//! `docs/results.md`. Forgery without a satisfying witness must grind the
//! transcript challenge (`≈2^-130` over two rounds, ROM).

use crate::commit::{commit_precomputed, twisted_ntt_matrix, Commitment, MatrixA};
use crate::error::{Error, Result};
use crate::params::{M_COLS, N_ROWS, PROOF_VERSION, Q, RESP_BOUND, TAU};
use crate::proof::{
    decode_poly, decode_u32, decode_z_packed, round_off, Proof, CHAL_OFF, PACK_OFF,
};
use crate::prover::{centered, digest_publics, expand_challenge, round_challenge, Publics};
use crate::ring::{add_mod, poly_mul_nwc, Poly, NCOEFFS};

/// Verify `proof` against `(a, y, t)`.
///
/// `t` is transcript-bound: it feeds every round challenge, so a proof
/// crafted for another `t` fails the linear equations under the recomputed
/// challenges. Exact packing sufficiency is the documented follow-up.
///
/// # Errors
/// * [`Error::MalformedEncoding`] on version/coefficient/reserved failure.
/// * [`Error::VerificationFailed`] on any equation, bound, or challenge mismatch.
pub fn verify(a: &MatrixA, y: &Commitment, t: u32, proof: &Proof) -> Result<()> {
    if proof.version != PROOF_VERSION {
        return Err(Error::MalformedEncoding);
    }
    // Reserved regions must be zero (pack tail, challenge tail).
    for b in &proof.body[PACK_OFF + 16..CHAL_OFF] {
        if *b != 0 {
            return Err(Error::MalformedEncoding);
        }
    }
    for b in &proof.body[CHAL_OFF + 32..] {
        if *b != 0 {
            return Err(Error::MalformedEncoding);
        }
    }
    // Pack `v` slots are canonically zero (the `v = ⟨r,c⋆w⟩` wire value was
    // removed: unenforced zeros would be a malleability vector — flipping
    // them changes no checked equation. Audit finding F24.)
    for b in proof.body[PACK_OFF + 4..PACK_OFF + 8]
        .iter()
        .chain(&proof.body[PACK_OFF + 12..PACK_OFF + 16])
    {
        if *b != 0 {
            return Err(Error::MalformedEncoding);
        }
    }
    let mut salt: [u8; 32] = [0; 32];
    salt.copy_from_slice(&proof.body[CHAL_OFF..CHAL_OFF + 32]);
    // Hoisted public transcript material + twisted-NTT matrix (hashed and
    // transformed once per call, not per round).
    let pubs: Publics = digest_publics(a, y);
    let antt: [[[u32; NCOEFFS]; M_COLS]; N_ROWS] = twisted_ntt_matrix(a);
    // Packing scalars range-checked (`< Q`; equation-checked in follow-up).
    for i in 0..2 * TAU {
        let v: u32 = decode_u32(&proof.body[PACK_OFF + i * 4..PACK_OFF + (i + 1) * 4])?;
        if v >= Q {
            return Err(Error::MalformedEncoding);
        }
    }
    for j in 0..TAU {
        verify_round(&antt, &pubs, y, t, &salt, j, proof)?;
    }
    Ok(())
}

/// One round: decode → challenge → linear equation → bounds.
fn verify_round(
    antt: &[[[u32; NCOEFFS]; M_COLS]; N_ROWS],
    pubs: &Publics,
    y: &Commitment,
    t: u32,
    salt: &[u8; 32],
    round: usize,
    proof: &Proof,
) -> Result<()> {
    let base: usize = round_off(round);
    // Decode `t1` (range-checked).
    let mut t1: [Poly; N_ROWS] = [[0; NCOEFFS]; N_ROWS];
    for (r, slot) in t1.iter_mut().enumerate() {
        *slot = decode_poly(&proof.body[base + r * NCOEFFS * 4..base + (r + 1) * NCOEFFS * 4])?;
    }
    // Decode `z` (packed, range-checked: canonicality + bound together).
    let zb: usize = base + crate::params::COMMIT_BYTES;
    let z: [Poly; M_COLS] = decode_z_packed(&proof.body[zb..zb + crate::params::Z_PACKED_BYTES])?;
    // Re-derive the challenge from the proof's own commitments (plus `t`).
    let u: u32 =
        decode_u32(&proof.body[PACK_OFF + (2 * round) * 4..PACK_OFF + (2 * round + 1) * 4])?;
    let c_seed: [u8; 32] =
        round_challenge(pubs, t, salt, round, &t1, u).map_err(|_| Error::VerificationFailed)?;
    let c: Poly = expand_challenge(&c_seed);
    // Linear equation: `A·z = t1 + c⋆y` per row (fast NTT path with
    // hoisted matrix; equivalence proven by `commit_fast_matches_naive`).
    let az: Commitment = commit_precomputed(antt, &z);
    for r in 0..N_ROWS {
        let cy: Poly = poly_mul_nwc(&c, &y[r]);
        for k in 0..NCOEFFS {
            if az[r][k] != add_mod(t1[r][k], cy[k]) {
                return Err(Error::VerificationFailed);
            }
        }
    }
    // Response bound (centered).
    let bound: i64 = i64::from(RESP_BOUND);
    for poly in &z {
        for coeff in poly {
            let v: i64 = centered(*coeff);
            if v < -bound || v > bound {
                return Err(Error::VerificationFailed);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::verify;
    use crate::commit::{derive_matrix, Commitment, MatrixA};
    use crate::params::M_COLS;
    use crate::prover::{prove_with_u_bias, sample_witness_for};
    use crate::ring::Poly;

    /// P8 gap demonstration, retained by design (see `docs/extraction.md` §1):
    /// the packing scalar `u` is transcript-bound but satisfies no verifier
    /// equation — a proof whose `u` values are all biased by +1 (consistently,
    /// through challenge re-derivation) still verifies whenever the linear
    /// equations hold. Packing closes through extraction, not equations;
    /// this test pins that architecture so nobody mistakes `(u, v)` for a
    /// soundness anchor.
    #[test]
    fn biased_packing_scalars_still_verify() {
        let a: MatrixA = derive_matrix(&[11; 32]).expect("matrix");
        let (w, y, t): ([Poly; M_COLS], Commitment, u32) = sample_witness_for(&a, &[22; 32]);
        let p: crate::proof::Proof =
            prove_with_u_bias(&a, &w, &y, t, &[33; 32], 1).expect("biased prove");
        assert!(verify(&a, &y, t, &p).is_ok());
    }
}
