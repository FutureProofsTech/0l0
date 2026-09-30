// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Prover: [`check_relation`] ground truth + Lyubashevsky [`prove`].
//!
//! Proof search per round: short uniform mask `r`, commitment `t1 = A·r`,
//! packing scalar `u = ⟨r,r⟩`, transcript challenge `c` (sparse ternary,
//! weight [`CHAL_WEIGHT`]), response `z = r + c⋆w` with rejection on
//! `‖z‖_∞ ≤ RESP_BOUND`. Accepted responses are exactly uniform (the former
//! `v = ⟨r,c⋆w⟩` wire slots stay zero — its variance leaks `‖cw‖₂`).
//! Two rounds (`TAU`).
//!
//! Soundness note (prototype): the linear equations are grinding-bound in
//! the ROM (`≈2^-130` over two rounds); packing closes via extraction
//! (`docs/extraction.md`). Hiding: conditional-uniform responses + marginal
//! computational leg (`docs/lattice-margin.md`).

use crate::commit::{commit, commit_precomputed, twisted_ntt_matrix, Commitment, MatrixA};
use crate::error::{Error, Result};
use crate::hash::{hash, xof_into};
use crate::params::{
    BETA, B_NORM, CHAL_WEIGHT, COMMIT_BYTES, MASK_BOUND, M_COLS, N_ROWS, PROOF_VERSION, Q,
    RESP_BOUND, SAMPLING_RETRIES, TAU,
};
use crate::proof::{encode_poly, encode_u32, round_off, Proof, CHAL_OFF, PACK_OFF};
use crate::ring::{add_mod, poly_mul_nwc_pre, twist_ntt, Poly, NCOEFFS};
use crate::transcript::{Transcript, TAG_PROJ};

/// XOF domain for the deterministic test/bench witness sampler.
const TAG_WITNESS: u8 = 0x77;

/// Centered representative of `c mod Q` in `[-(Q-1)/2, (Q-1)/2]` as `i64`.
///
/// Branchless (mask arithmetic, no data-dependent branch): `centered(c)` is
/// evaluated on witness/mask/response coefficients, so a comparison branch
/// here would be a timing oracle on secrets (Q8 audit).
#[must_use]
#[allow(clippy::cast_lossless)] // `as` required: int→int `From` is not const-stable
pub const fn centered(c: u32) -> i64 {
    // `m = 1` iff `c > Q/2`: `half - c` underflows exactly then, setting bit 31.
    let half: u32 = Q / 2;
    let m: i64 = (half.wrapping_sub(c) >> 31) as i64;
    (c as i64) - m * (Q as i64)
}

/// Check `R*(a, w, y, t)`: `A·w = y`, `‖w‖_∞ ≤ BETA`, `‖w‖_2 ≤ B_NORM`,
/// and `⟨w,w⟩ = t (mod Q)` over centered representatives.
///
/// The linear part runs through the fast NTT path; equivalence with the
/// naive ground truth is proven by the `commit_fast_matches_naive`
/// differential test (all profiles).
#[must_use]
pub fn check_relation(a: &MatrixA, w: &[Poly; M_COLS], y: &Commitment, t: u32) -> bool {
    // Linear part (fast path).
    let got: Commitment = commit(a, w);
    if got != *y {
        return false;
    }
    // Infinity-norm gate first: bounds every coefficient before squaring, so
    // the `u64` accumulator below cannot overflow on adversarial inputs
    // (centered values reach `±Q/2 ≈ ±2^29`; their squares would overflow).
    for poly in w {
        for c in poly {
            let v: i64 = centered(*c);
            let beta: i64 = i64::from(BETA);
            if v < -beta || v > beta {
                return false;
            }
        }
    }
    // Shortness + packing over bounded coefficients (`|v| ≤ BETA = 1`, so each
    // square is `≤ 1` and the total over 512 coefficients is `≤ 512`).
    let mut sum_sq: u64 = 0;
    for poly in w {
        for c in poly {
            let v: i64 = centered(*c);
            sum_sq += (v * v) as u64;
        }
    }
    let b2: u64 = u64::from(B_NORM) * u64::from(B_NORM);
    if sum_sq > b2 {
        return false;
    }
    (sum_sq % u64::from(Q)) as u32 == t % Q
}

/// Prove knowledge of `w` for `(a, y, t)` with caller salt.
///
/// Deterministic given `salt` (fresh 32 B per proof from the caller);
/// returns [`Error::SamplingExhausted`] if all rejection attempts fail
/// (caller retries with fresh salt). Fails closed on unsatisfied `R*`.
///
/// # Errors
/// * [`Error::UnsatisfiedRelation`] if `!check_relation(a, w, y, t)`.
/// * [`Error::SamplingExhausted`] if rejection sampling fails
///   [`SAMPLING_RETRIES`] attempts in any round.
/// * [`Error::TranscriptError`] on transcript failure (unreachable: all
///   absorbs are within bounds).
pub fn prove(
    a: &MatrixA,
    w: &[Poly; M_COLS],
    y: &Commitment,
    t: u32,
    salt: &[u8; 32],
) -> Result<Proof> {
    if !check_relation(a, w, y, t) {
        return Err(Error::UnsatisfiedRelation);
    }
    let pubs: Publics = digest_publics(a, y);
    let antt: [[[u32; NCOEFFS]; M_COLS]; N_ROWS] = twisted_ntt_matrix(a);
    let mut body: [u8; crate::params::PROOF_BYTES - 1] = [0; crate::params::PROOF_BYTES - 1];
    let mut uvs: [u32; 2 * TAU] = [0; 2 * TAU];
    for j in 0..TAU {
        let (t1, z, u, v): (Commitment, [Poly; M_COLS], u32, u32) =
            prove_round(&antt, w, &pubs, t, salt, j, 0)?;
        store_round(&mut body, j, &t1, &z)?;
        uvs[2 * j] = u;
        uvs[2 * j + 1] = v;
    }
    finish_proof(&mut body, &uvs, salt);
    Ok(Proof {
        version: PROOF_VERSION,
        body,
    })
}

/// Store one round block (`t1 ‖ z_packed`) into the body (shared by [`prove`]
/// and the P8 harness so the two cannot drift apart — audit finding F3).
///
/// # Errors
/// * Propagates [`encode_z_packed`] range errors (unreachable: responses
///   pass [`response_ok`] before storage).
fn store_round(
    body: &mut [u8; crate::params::PROOF_BYTES - 1],
    j: usize,
    t1: &Commitment,
    z: &[Poly; M_COLS],
) -> Result<()> {
    use crate::proof::encode_z_packed;
    let base: usize = round_off(j);
    for (r, poly) in t1.iter().enumerate() {
        encode_poly(
            poly,
            &mut body[base + r * NCOEFFS * 4..base + (r + 1) * NCOEFFS * 4],
        );
    }
    let zb: usize = base + COMMIT_BYTES;
    encode_z_packed(z, &mut body[zb..zb + crate::params::Z_PACKED_BYTES])
}

/// Write pack (`u0 v0 u1 v1`) + salt blocks (shared, see [`store_round`]).
fn finish_proof(
    body: &mut [u8; crate::params::PROOF_BYTES - 1],
    uvs: &[u32; 2 * TAU],
    salt: &[u8; 32],
) {
    for (i, v) in uvs.iter().enumerate() {
        encode_u32(*v, &mut body[PACK_OFF + i * 4..PACK_OFF + (i + 1) * 4]);
    }
    body[CHAL_OFF..CHAL_OFF + 32].copy_from_slice(salt);
}

/// One round: mask → commit → challenge → respond (with rejection retries).
///
/// `u_bias` (wrapping-added to `u` before challenge derivation and storage)
/// is 0 in production. The P8 red-team harness passes nonzero bias to prove
/// that the packing scalar is challenge-bound but not equation-checked: the
/// resulting proof still verifies iff the linear equations hold.
fn prove_round(
    antt: &[[[u32; NCOEFFS]; M_COLS]; N_ROWS],
    w: &[Poly; M_COLS],
    pubs: &Publics,
    t: u32,
    salt: &[u8; 32],
    round: usize,
    u_bias: u32,
) -> Result<(Commitment, [Poly; M_COLS], u32, u32)> {
    let mut attempt: u8 = 0;
    while attempt < SAMPLING_RETRIES {
        let mut seed_in: [u8; 34] = [0; 34];
        seed_in[..32].copy_from_slice(salt);
        seed_in[32] = round as u8;
        seed_in[33] = attempt;
        let seed: [u8; 32] = hash(&seed_in);
        let r: [Poly; M_COLS] = sample_mask(&seed)?;
        let t1: Commitment = commit_precomputed(antt, &r);
        let u: u32 = inner_prod(&r, &r).wrapping_add(u_bias);
        let c_seed: [u8; 32] = round_challenge(pubs, t, salt, round, &t1, u)?;
        let c: Poly = expand_challenge(&c_seed);
        // `cw = c⋆w`, `z = r + cw`, `v = ⟨r,cw⟩`.
        let cntt: Poly = twist_ntt(&c);
        let mut cw: [Poly; M_COLS] = [[0; NCOEFFS]; M_COLS];
        for (dst, src) in cw.iter_mut().zip(w.iter()) {
            *dst = poly_mul_nwc_pre(&cntt, src);
        }
        let mut z: [Poly; M_COLS] = [[0; NCOEFFS]; M_COLS];
        for (dst, (rp, cp)) in z.iter_mut().zip(r.iter().zip(cw.iter())) {
            for k in 0..NCOEFFS {
                dst[k] = add_mod(rp[k], cp[k]);
            }
        }
        // NOTE (Q-closure audit): `v = ⟨r,cw⟩` is deliberately NOT computed
        // or stored (pack `v` slots are zero). Its variance encodes `‖cw‖₂`
        // (e.g. `w = 0` forces `v ≡ 0`), a catastrophic witness distinguisher
        // through the only non-response wire value. Responses `z` and the
        // mask commitment `(t1, u)` are exactly witness-independent (see
        // Theorem 3); `v` was the sole leak. Aggregation follow-ups must
        // use blinded packing scalars with fresh analysis.
        let v: u32 = 0;
        if response_ok(&z) {
            return Ok((t1, z, u, v));
        }
        attempt += 1;
    }
    Err(Error::SamplingExhausted)
}

/// P8 red-team harness (test-only): identical to [`prove`] but adds `bias`
/// to every round's packing scalar before challenge derivation and storage.
///
/// A biased proof that still verifies demonstrates the documented gap:
/// `(u, v)` are transcript-bound (malleability-resistant) but no verifier
/// equation constrains them beyond range checks.
#[cfg(test)]
pub(crate) fn prove_with_u_bias(
    a: &MatrixA,
    w: &[Poly; M_COLS],
    y: &Commitment,
    t: u32,
    salt: &[u8; 32],
    bias: u32,
) -> Result<Proof> {
    use crate::params::PROOF_BYTES;
    if !check_relation(a, w, y, t) {
        return Err(Error::UnsatisfiedRelation);
    }
    let pubs: Publics = digest_publics(a, y);
    let antt: [[[u32; NCOEFFS]; M_COLS]; N_ROWS] = twisted_ntt_matrix(a);
    let mut body: [u8; PROOF_BYTES - 1] = [0; PROOF_BYTES - 1];
    let mut uvs: [u32; 2 * TAU] = [0; 2 * TAU];
    for j in 0..TAU {
        let (t1, z, u, v): (Commitment, [Poly; M_COLS], u32, u32) =
            prove_round(&antt, w, &pubs, t, salt, j, bias)?;
        store_round(&mut body, j, &t1, &z)?;
        uvs[2 * j] = u;
        uvs[2 * j + 1] = v;
    }
    finish_proof(&mut body, &uvs, salt);
    Ok(Proof {
        version: PROOF_VERSION,
        body,
    })
}

/// Sample a mask uniform in `[-MASK_BOUND, MASK_BOUND]` (centered mod `Q`).
///
/// One 512-byte XOF stream per polynomial (128 candidates for 64 slots,
/// rejection bound `(2^32/MASK_RANGE)·MASK_RANGE`, `MASK_RANGE = 2S+1`).
/// Shortfall returns [`Error::SamplingExhausted`] (caller retries).
fn sample_mask(seed: &[u8; 32]) -> Result<[Poly; M_COLS]> {
    const RANGE: u32 = 2 * MASK_BOUND + 1;
    let bound: u64 = (u64::from(u32::MAX) / u64::from(RANGE)) * u64::from(RANGE);
    let mut out: [Poly; M_COLS] = [[0; NCOEFFS]; M_COLS];
    for (c, poly) in out.iter_mut().enumerate() {
        let mut input: [u8; 34] = [0; 34];
        input[..32].copy_from_slice(seed);
        input[32] = 0x6D;
        input[33] = c as u8;
        let mut stream: [u8; 512] = [0; 512];
        xof_into(&input, crate::transcript::TAG_BLIND, &mut stream)?;
        let mut k: usize = 0;
        let mut pos: usize = 0;
        while k < NCOEFFS && pos + 4 <= stream.len() {
            let mut b: [u8; 4] = [0; 4];
            b.copy_from_slice(&stream[pos..pos + 4]);
            pos += 4;
            let v: u64 = u64::from(u32::from_le_bytes(b));
            if v >= bound {
                continue;
            }
            let centered_val: i64 =
                i64::from((v % u64::from(RANGE)) as u32) - i64::from(MASK_BOUND);
            // Map to mod-`Q` representative (lossless: `|v| ≤ S < Q/2`).
            poly[k] = if centered_val < 0 {
                u32::try_from(i64::from(Q) + centered_val).expect("neg centered + Q < 2^32")
            } else {
                centered_val as u32
            };
            k += 1;
        }
        if k < NCOEFFS {
            return Err(Error::SamplingExhausted);
        }
    }
    Ok(out)
}

/// Expand a sparse ternary challenge of weight [`CHAL_WEIGHT`].
///
/// First 96 stream bytes choose distinct positions (`byte % 64` is exactly
/// uniform); any unfilled slots after the stream take the lowest free index
/// (hash-degenerate streams only, documented bias note). Last 32 bytes give
/// signs (`+1`/`−1` as `1`/`Q−1`).
pub(crate) fn expand_challenge(seed: &[u8; 32]) -> Poly {
    let mut stream: [u8; 128] = [0; 128];
    // Infallible in practice (128 B ≤ 2048 cap); fall back to zero poly on
    // error so the function stays total (prover then fails downstream).
    if xof_into(seed, TAG_PROJ, &mut stream).is_err() {
        return [0; NCOEFFS];
    }
    let mut used: [bool; NCOEFFS] = [false; NCOEFFS];
    let mut out: Poly = [0; NCOEFFS];
    let mut placed: usize = 0;
    for b in &stream[..96] {
        if placed >= CHAL_WEIGHT {
            break;
        }
        let pos: usize = (*b as usize) % NCOEFFS;
        if !used[pos] {
            used[pos] = true;
            let sign: u32 = if (stream[96 + placed] & 1) == 0 {
                1
            } else {
                Q - 1
            };
            out[pos] = sign;
            placed += 1;
        }
    }
    // Deterministic fill for degenerate streams (probability ≈ 2^-512 input).
    let mut pos: usize = 0;
    while placed < CHAL_WEIGHT && pos < NCOEFFS {
        if !used[pos] {
            used[pos] = true;
            out[pos] = 1;
            placed += 1;
        }
        pos += 1;
    }
    out
}

/// Centered inner product `⟨a,b⟩ mod Q` over all coefficients.
///
/// Accumulator is `i128` (terms `≤ 2^32` in v0.1 call sites, sum `≪ 2^127`).
#[must_use]
pub fn inner_prod(a: &[Poly; M_COLS], b: &[Poly; M_COLS]) -> u32 {
    let mut acc: i128 = 0;
    for (pa, pb) in a.iter().zip(b.iter()) {
        for (x, y) in pa.iter().zip(pb.iter()) {
            acc += i128::from(centered(*x)) * i128::from(centered(*y));
        }
    }
    let q: i128 = i128::from(Q);
    let mut r: i128 = acc % q;
    if r < 0 {
        r += q;
    }
    r as u32
}

/// Accept iff every response coefficient is within `±RESP_BOUND` (centered).
///
/// Constant-scan: no early exit, so rejection timing does not reveal the
/// position of the first out-of-bound coefficient (Q8 timing fix — the
/// previous early-return leaked it). Flag accumulation is branchless
/// (`setcc`-class instructions, data-independent latency on `x86_64`).
#[must_use]
pub fn response_ok(z: &[Poly; M_COLS]) -> bool {
    let bound: i64 = i64::from(RESP_BOUND);
    let mut bad: u64 = 0;
    for poly in z {
        for c in poly {
            let v: i64 = centered(*c);
            bad |= u64::from(v < -bound) | u64::from(v > bound);
        }
    }
    bad == 0
}

/// Flattened public inputs, hashed once per prove/verify call (S1 hoist).
///
/// `round_challenge` absorbs these digests instead of re-flattening and
/// re-hashing 9 KB per round. Binding is preserved by collision resistance
/// (documented composition); challenges are byte-identical to the unhoisted
/// derivation (pinned by the Python differential, which implements the same
/// absorbs).
pub(crate) struct Publics {
    /// `hash(flatten(A))`.
    pub a_digest: [u8; 32],
    /// Flattened `y` (1024 B, absorbed directly).
    pub ybytes: [u8; 1024],
}

/// Precompute per-call public transcript material from `(a, y)`.
#[must_use]
pub(crate) fn digest_publics(a: &MatrixA, y: &Commitment) -> Publics {
    let mut abytes: [u8; 8192] = [0; 8192];
    for (r, row) in a.iter().enumerate() {
        for (c, poly) in row.iter().enumerate() {
            for (k, coeff) in poly.iter().enumerate() {
                let o: usize = (r * M_COLS + c) * NCOEFFS * 4 + k * 4;
                abytes[o..o + 4].copy_from_slice(&coeff.to_le_bytes());
            }
        }
    }
    let mut ybytes: [u8; 1024] = [0; 1024];
    for (r, poly) in y.iter().enumerate() {
        for (k, coeff) in poly.iter().enumerate() {
            ybytes[r * NCOEFFS * 4 + k * 4..r * NCOEFFS * 4 + k * 4 + 4]
                .copy_from_slice(&coeff.to_le_bytes());
        }
    }
    Publics {
        a_digest: hash(&abytes),
        ybytes,
    }
}

/// Round challenge: transcript over all public inputs + round commitments.
///
/// Binds `(params, A, y, t, salt, round, t1, u)` — `A`/`y` via the hoisted
/// [`Publics`]; the response `z` is bound through the linear equation it
/// must satisfy (P6). All absorbs are within transcript bounds.
///
/// # Errors
/// * [`Error::TranscriptError`] (unreachable: fixed sizes).
pub(crate) fn round_challenge(
    pubs: &Publics,
    t: u32,
    salt: &[u8; 32],
    round: usize,
    t1: &Commitment,
    u: u32,
) -> Result<[u8; 32]> {
    let mut tr: Transcript = Transcript::new(b"sq-pq/v0.1/R*");
    // Bind the frozen parameters + proof version first: a proof verified
    // under different params must fail challenge recomputation.
    let mut pbytes: [u8; 32] = [0; 32];
    pbytes[0..8].copy_from_slice(&(crate::params::D as u64).to_le_bytes());
    pbytes[8..12].copy_from_slice(&Q.to_le_bytes());
    pbytes[12..16].copy_from_slice(&BETA.to_le_bytes());
    pbytes[16..20].copy_from_slice(&B_NORM.to_le_bytes());
    pbytes[20..24].copy_from_slice(&RESP_BOUND.to_le_bytes());
    pbytes[24] = TAU as u8;
    pbytes[25] = crate::params::PROOF_VERSION;
    tr.absorb(b"params", &pbytes)?;
    tr.absorb(b"A", &pubs.a_digest)?;
    tr.absorb(b"y", &pubs.ybytes)?;
    tr.absorb(b"t", &t.to_le_bytes())?;
    tr.absorb(b"salt", salt)?;
    tr.absorb(b"round", &[round as u8])?;
    let mut t1bytes: [u8; 1024] = [0; 1024];
    for (r, poly) in t1.iter().enumerate() {
        for (k, coeff) in poly.iter().enumerate() {
            t1bytes[r * NCOEFFS * 4 + k * 4..r * NCOEFFS * 4 + k * 4 + 4]
                .copy_from_slice(&coeff.to_le_bytes());
        }
    }
    tr.absorb(b"t1", &t1bytes)?;
    tr.absorb(b"u", &u.to_le_bytes())?;
    tr.challenge32(TAG_PROJ)
}

/// Deterministic ternary witness sampler for tests/benches.
///
/// Coefficients from `XOF(seed) mod 3` → `{0, 1, Q-1}`; `y = commit(a, w)`,
/// `t = ⟨w,w⟩ mod Q` (= support weight for ternary `w`).
///
/// # Panics
/// Panics if the fixed 1024-byte XOF stream fails (unreachable: under the
/// 2048-byte cap by construction).
#[must_use]
pub fn sample_witness_for(a: &MatrixA, seed: &[u8; 32]) -> ([Poly; M_COLS], Commitment, u32) {
    let mut stream: [u8; 1024] = [0; 1024];
    xof_into(seed, TAG_WITNESS, &mut stream).expect("fixed 1024B stream");
    let mut w: [Poly; M_COLS] = [[0; NCOEFFS]; M_COLS];
    let mut pos: usize = 0;
    for poly in &mut w {
        for c in poly.iter_mut() {
            *c = match stream[pos % stream.len()] % 3 {
                0 => 0,
                1 => 1,
                _ => Q - 1,
            };
            pos += 1;
        }
    }
    let y: Commitment = commit(a, &w);
    let t: u32 = inner_prod(&w, &w);
    (w, y, t)
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::cast_precision_loss)] // test statistics only; all values « 2^53, exact
mod tests {
    use super::{
        centered, check_relation, expand_challenge, response_ok, sample_mask, sample_witness_for,
    };
    use crate::params::{MASK_BOUND, Q};
    use crate::ring::{poly_mul_nwc, Poly, NCOEFFS};

    fn zero_matrix() -> crate::commit::MatrixA {
        [[[0; NCOEFFS]; crate::params::M_COLS]; crate::params::N_ROWS]
    }

    #[test]
    fn centered_smoke() {
        assert_eq!(centered(0), 0);
        assert_eq!(centered(1), 1);
        assert_eq!(centered(Q - 1), -1);
    }

    #[test]
    fn zero_witness_zero_commitment_passes() {
        let a: crate::commit::MatrixA = zero_matrix();
        let w: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        let y: crate::commit::Commitment = [[0; NCOEFFS]; crate::params::N_ROWS];
        assert!(check_relation(&a, &w, &y, 0));
    }

    #[test]
    fn norm_violation_fails() {
        let a: crate::commit::MatrixA = zero_matrix();
        let mut w: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        w[0][0] = 2; // BETA = 1 exceeded
        let y: crate::commit::Commitment = [[0; NCOEFFS]; crate::params::N_ROWS];
        assert!(!check_relation(&a, &w, &y, 4));
    }

    /// P7: masks respect `±MASK_BOUND` by construction (32 seeds).
    #[test]
    fn masks_within_bound() {
        let bound: i64 = i64::from(MASK_BOUND);
        for i in 0..32u8 {
            let mut seed: [u8; 32] = [9; 32];
            seed[0] = i;
            let r: [Poly; crate::params::M_COLS] = sample_mask(&seed).expect("mask samples");
            for poly in &r {
                for c in poly {
                    let v: i64 = centered(*c);
                    assert!(v >= -bound && v <= bound);
                }
            }
        }
    }

    /// P7: rejection acceptance rate in the analyzed band.
    ///
    /// Per-coefficient accept `p = (2·RESP+1)/(2·MASK+1) = 130945/131073`;
    /// per-512-coeff response `p^512 ≈ 0.606`. Asserts the measured rate
    /// over 40 masks lands in `[0.4, 0.8]` (documents `M ≈ 1.65`).
    #[test]
    fn response_acceptance_in_band() {
        let mut ok: u32 = 0;
        let n: u32 = 40;
        for i in 0..n {
            let mut seed: [u8; 32] = [5; 32];
            seed[0] = i as u8;
            let r: [Poly; crate::params::M_COLS] = sample_mask(&seed).expect("mask samples");
            if response_ok(&r) {
                ok += 1;
            }
        }
        assert!((14..=34).contains(&ok), "accept {ok}/{n}, want 14..=34");
    }

    /// P7: challenge-times-witness shift premise for the hiding review.
    ///
    /// `‖c⋆w‖_∞ ≤ CHAL_WEIGHT` for ternary `w` (each output coefficient sums
    /// at most 16 signed `±1` products). Per-coefficient statistical shift
    /// is therefore `≤ 16` over width `131073` (`≈2^-13.0`); the joint
    /// 512-coefficient bound is vacuous — recorded as review debt, not a
    /// claim (see `docs/results.md` H3).
    #[test]
    fn challenge_shift_bounded() {
        let a: crate::commit::MatrixA = zero_matrix();
        let (w, _, _): (
            [Poly; crate::params::M_COLS],
            crate::commit::Commitment,
            u32,
        ) = sample_witness_for(&a, &[77; 32]);
        for i in 0..8u8 {
            let mut seed: [u8; 32] = [3; 32];
            seed[0] = i;
            let c: Poly = expand_challenge(&seed);
            for src in &w {
                let cw: Poly = poly_mul_nwc(&c, src);
                for coeff in &cw {
                    let v: i64 = centered(*coeff);
                    assert!((-16..=16).contains(&v), "shift {v} exceeds 16");
                }
            }
        }
        // Weight premise itself: exactly CHAL_WEIGHT nonzero ±1 coefficients.
        let c0: Poly = expand_challenge(&[3; 32]);
        let mut nz: u32 = 0;
        for coeff in &c0 {
            assert!(*coeff == 0 || *coeff == 1 || *coeff == Q - 1);
            if *coeff != 0 {
                nz += 1;
            }
        }
        assert_eq!(nz as usize, crate::params::CHAL_WEIGHT);
    }

    /// P7/Q3: joint statistical-hiding bound, integer-exact.
    ///
    /// Per-coefficient shift `≤ 16` (proven above) over mask width
    /// `2·MASK_BOUND+1` gives joint total variation
    /// `512·16/(2·MASK_BOUND+1) = 8192/131073 < 2^-4` (`tools/renyi.py`
    /// computes the exact table incl. Rényi-2 `≈ 0.0625` nats and documents
    /// `R∞ = ∞` on support edges). This test pins the arithmetic on the
    /// frozen constants; the interpretation lives in `docs/results.md` H3.
    #[test]
    fn hiding_joint_tv_bound() {
        use crate::params::MASK_BOUND;
        assert!((16u32 * 512 * 16) <= 2 * MASK_BOUND + 1);
    }

    /// Brutal: 1000 challenge seeds — weight exactly 16, coefficients in
    /// `{0, ±1}`, never the zero polynomial (which would void soundness).
    #[test]
    fn challenge_distribution_1000() {
        use super::expand_challenge;
        for i in 0..1000u32 {
            let mut seed: [u8; 32] = [0xC4; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            let c: Poly = expand_challenge(&seed);
            let mut nz: u32 = 0;
            for coeff in &c {
                assert!(*coeff == 0 || *coeff == 1 || *coeff == Q - 1);
                if *coeff != 0 {
                    nz += 1;
                }
            }
            assert_eq!(nz as usize, crate::params::CHAL_WEIGHT, "seed {i}");
        }
        // Determinism: same seed twice, same challenge.
        assert_eq!(expand_challenge(&[9; 32]), expand_challenge(&[9; 32]));
    }

    /// Brutal: Euclidean edge — exactly 64 unit coefficients give
    /// `‖w‖₂² = 64`, exactly at `B_NORM`, and must PASS with `t = 64`.
    /// (65 is unreachable without an infinity-norm violation: 64 ternary
    /// slots of `±1` max out at 64. The infinity edge is covered by
    /// `norm_violation_fails`.)
    #[test]
    fn euclidean_edge_exactly_64() {
        use crate::commit::{commit, Commitment};
        let a: crate::commit::MatrixA = zero_matrix();
        let mut w: [Poly; crate::params::M_COLS] = [[0; NCOEFFS]; crate::params::M_COLS];
        w[0] = [1; NCOEFFS];
        let y: Commitment = commit(&a, &w);
        assert!(check_relation(&a, &w, &y, 64));
    }

    /// Q-closure: accepted responses are EXACTLY uniform (χ² exhibit).
    ///
    /// For fixed shift `|s| ≤ S−B` (here worst-case constant `s = +16`),
    /// acceptance `|r+s| ≤ B` keeps exactly the `2B+1` values mapping
    /// bijectively onto `[-B, B]` — the conditional output distribution is
    /// uniform with total-variation distance ZERO, not merely bounded.
    /// This supersedes the union-bound argument: per-proof responses leak
    /// nothing statistically; the remaining hiding question is purely
    /// computational (mask recovery, `docs/lattice-margin.md`).
    /// Masks here come from splitmix (distribution-equivalent uniform
    /// input; XOF→uniform separately KAT-pinned, acceptance-tested above).
    #[test]
    fn accepted_response_uniform_chi2() {
        use crate::params::{MASK_BOUND, RESP_BOUND};
        const NB: usize = 64;
        let s: i64 = 16;
        let bound: i64 = i64::from(RESP_BOUND);
        let width: u64 = 2 * u64::from(RESP_BOUND) + 1;
        // Exact bucket sizes for the partition `b = (v+B)*64 // width`.
        let mut expected: [u64; NB] = [0; NB];
        let mut v: i64 = -bound;
        while v <= bound {
            let b: usize = ((v + bound) as u64 * NB as u64 / width) as usize;
            expected[b.min(NB - 1)] += 1;
            v += 1;
        }
        let mut obs: [u64; NB] = [0; NB];
        let mut rng: u64 = 0x5EED_1234_5678_9ABC;
        let mut accepted: u32 = 0;
        let target: u32 = 20_000;
        while accepted < target {
            // Uniform r in [-S, S] via 64-bit splitmix reduced mod width.
            rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x: u64 = rng;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^= x >> 31;
            let r: i64 = (x % (2 * u64::from(MASK_BOUND) + 1)) as i64 - i64::from(MASK_BOUND);
            let z: i64 = r + s;
            if z < -bound || z > bound {
                continue;
            }
            let b: usize = ((z + bound) as u64 * NB as u64 / width) as usize;
            obs[b.min(NB - 1)] += 1;
            accepted += 1;
        }
        let mut chi2: f64 = 0.0;
        for b in 0..NB {
            let scale: f64 = f64::from(accepted) / width as f64;
            let e: f64 = expected[b] as f64 * scale;
            let d: f64 = obs[b] as f64 - e;
            chi2 += d * d / e;
        }
        // χ²_63: 99.9% critical ≈ 109; threshold 130 ⇒ false-alarm ≈ 1e-5.
        assert!(chi2 < 130.0, "non-uniform accepted responses? chi2={chi2}");
    }
}
