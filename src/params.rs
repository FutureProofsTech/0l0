// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Frozen v0.1 parameters for `R*` (spec freeze P0).
//!
//! Relation: short `w ∈ R_q^m` with `A·w = y`, `‖w‖_∞ ≤ BETA`,
//! `‖w‖_2 ≤ B_NORM`, and one quadratic packing check `⟨w,w⟩ = T`.
//! See `docs/params-rationale.md` for why each value was chosen and what is
//! explicitly *not* claimed (no reduction proof at prototype bar).

/// Ring degree: `R_q = Z_q[X]/(X^D + 1)`, power of two for NTT.
pub const D: usize = 64;
/// Modulus `q = 107_375_0017 = 2^30 + 2^13 + 1` (prime, `q ≡ 1 mod 128`,
/// so 64-th roots of unity exist for a from-scratch NTT of size 64).
/// Fits in `u32`; products of two `< q` values fit in `u64`.
pub const Q: u32 = 1_073_750_017;
/// Commitment matrix rows over `R_q`.
pub const N_ROWS: usize = 4;
/// Witness width (ring elements).
pub const M_COLS: usize = 8;
/// Infinity-norm bound for honest witnesses.
pub const BETA: u32 = 1;
/// Euclidean-norm bound (`‖w‖_2 ≤ B_NORM` over all `M_COLS*D` coefficients).
/// Ternary coeffs give `‖w‖_2 ≤ sqrt(512) ≈ 22.6`; bound leaves margin.
pub const B_NORM: u32 = 64;
/// Mask half-width `S`: masks uniform in `[-S, S]` (centered mod `Q`).
pub const MASK_BOUND: u32 = 65_536;
/// Response acceptance bound: accept iff `‖z‖_∞ ≤ RESP_BOUND`.
/// Slack `MASK_BOUND − RESP_BOUND = 64` covers `‖c⋆w‖_∞ ≤ 16` (challenge
/// weight 16 × ternary witness) with margin.
pub const RESP_BOUND: u32 = 65_472;
/// Challenge weight: number of nonzero `±1` coefficients per round.
pub const CHAL_WEIGHT: usize = 16;
/// Fixed rejection-sampling retry budget for the prover (deterministic salt
/// derivation; verifier never retries).
pub const SAMPLING_RETRIES: u8 = 8;
/// Soundness repetitions (independent mask/challenge draws per round).
pub const TAU: usize = 2;

/// Proof-size budget (bytes, wire, versioned). Target: `≤ 10 KB` envelope.
///
/// Body layout per round: mask commitment `t1` ([`COMMIT_BYTES`]) +
/// response `z` ([`Z_BYTES`]); then one packing block ([`QUAD_OPEN_BYTES`]:
/// scalars `u = ⟨r,r⟩`, `v = ⟨r,c⋆w⟩` + reserved) and one challenge block
/// ([`CHALLENGE_BYTES`]: master salt + reserved; challenge seeds re-derive
/// from the transcript).
pub const PROOF_VERSION: u8 = 2;
/// Ajtai commitment opening (`N_ROWS` ring elements).
pub const COMMIT_BYTES: usize = N_ROWS * D * 4;
/// Response block per repetition, v1 unpacked (`M_COLS` ring elements).
/// Superseded by [`Z_PACKED_BYTES`] in v2; kept for the version history.
pub const Z_BYTES: usize = M_COLS * D * 4;
/// Response block per repetition, v2 packed: 512 coefficients × 17 bits.
///
/// 8704 bits = 1088 bytes exactly (no padding bits). Valid codewords are
/// offset-binary values in `[64, 131008]` (centered `±RESP_BOUND`); a single
/// range check enforces canonicality and the response bound together.
pub const Z_PACKED_BYTES: usize = 1088;
/// Packed-word valid range `[Z_PACK_MIN, Z_PACK_MAX]` (offset-binary
/// `centered + 65536` for `|centered| ≤ RESP_BOUND = 65472`).
pub const Z_PACK_MIN: u32 = 64;
/// See [`Z_PACK_MIN`].
pub const Z_PACK_MAX: u32 = 131_008;
/// Packing block: `u[4] ‖ v[4]` + reserved.
pub const QUAD_OPEN_BYTES: usize = D * 4 + 32;
/// Challenge block: master salt (32 B) + reserved (32 B).
pub const CHALLENGE_BYTES: usize = 64;
/// Total wire bytes: 1 version byte + `TAU` rounds + packing + challenge.
/// Must stay `≤ 10240` (10 KB envelope) with margin.
pub const PROOF_BYTES: usize =
    1 + TAU * (COMMIT_BYTES + Z_PACKED_BYTES) + QUAD_OPEN_BYTES + CHALLENGE_BYTES;

const _: () = assert!(D == 64, "NTT size assumption");
const _: () = assert!(Q == 1_073_750_017, "modulus assumption");
const _: () = assert!(M_COLS * D == 512, "witness coefficient count");
const _: () = assert!(
    MASK_BOUND - RESP_BOUND == 64,
    "rejection slack covers ‖c⋆w‖"
);
const _: () = assert!(TAU < 256, "round index fits one transcript byte");
const _: () = assert!(
    M_COLS * D * 17 == Z_PACKED_BYTES * 8,
    "exact packing, no pad bits"
);
const _: () = assert!(
    Z_PACK_MAX - Z_PACK_MIN == 2 * RESP_BOUND,
    "pack range matches response bound"
);
const _: () = assert!(PROOF_BYTES <= 10_240, "proof must fit 10 KB envelope");
const _: () = assert!(
    PROOF_BYTES >= 2048,
    "budget sanity: proofs are concise, not tiny"
);

#[cfg(test)]
mod tests {
    use super::{B_NORM, COMMIT_BYTES, PROOF_BYTES};

    #[test]
    fn budget_in_envelope() {
        assert!(PROOF_BYTES <= 10_240);
        assert!(PROOF_BYTES >= 2048);
        assert_eq!(COMMIT_BYTES, 4 * 64 * 4);
        assert!(B_NORM >= 23, "must cover ternary witnesses");
    }
}
