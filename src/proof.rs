// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Versioned proof wire format (v2: packed responses, canonical).
//!
//! Body layout (round blocks: `t1` LE32 coeff-major; `z` 17-bit packed
//! LSB-first coeff-major):
//! ```text
//! round j (2112 B each, j = 0..TAU):
//!   t1_j : mask commitment, 4 polys  (1024 B)
//!   z_j  : response, 512 coeffs × 17 bits (1088 B, no pad bits)
//! pack (288 B): u0[4] 0[4] u1[4] 0[4] ‖ reserved (272 B zero)
//! (the `v = ⟨r,c⋆w⟩` slots stay zero: its variance leaks `‖cw‖₂`)
//! chal (64 B):  master salt (32 B) ‖ reserved (32 B zero)
//! ```
//! Total body `4576 B` + 1 version byte = [`PROOF_BYTES`]. Packed words
//! outside `[Z_PACK_MIN, Z_PACK_MAX]` are non-canonical
//! ([`Error::MalformedEncoding`]); `t1` coefficients `< Q` as before.
//! v1 (unpacked, 6497 B) stopped verifying at the v2 cutover.

use crate::error::{Error, Result};
use crate::params::{
    CHALLENGE_BYTES, COMMIT_BYTES, M_COLS, PROOF_BYTES, PROOF_VERSION, QUAD_OPEN_BYTES, TAU,
    Z_PACKED_BYTES,
};
use crate::ring::{Poly, NCOEFFS};

/// One round block: `t1 ‖ z_packed`.
pub const ROUND_BYTES: usize = COMMIT_BYTES + Z_PACKED_BYTES;
/// Offset of round `j` inside the body.
#[must_use]
pub const fn round_off(j: usize) -> usize {
    j * ROUND_BYTES
}
/// Offset of the packing block inside the body.
pub const PACK_OFF: usize = TAU * ROUND_BYTES;
/// Offset of the challenge block inside the body.
pub const CHAL_OFF: usize = TAU * ROUND_BYTES + QUAD_OPEN_BYTES;

const _: () = assert!(
    CHAL_OFF + CHALLENGE_BYTES == PROOF_BYTES - 1,
    "layout fills body"
);
const _: () = assert!(ROUND_BYTES == 2112, "round layout");
const _: () = assert!(PROOF_BYTES == 4577, "v2 wire size");

/// Versioned proof container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// Format version (must equal [`PROOF_VERSION`]).
    pub version: u8,
    /// Opaque body (structured in P5/P6; reserved zero until then).
    pub body: [u8; PROOF_BYTES - 1],
}

const _: () = assert!(PROOF_BYTES > 1, "header fits");

impl Proof {
    /// Serialize canonically (`version || body`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PROOF_BYTES] {
        let mut out: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        out[0] = self.version;
        out[1..].copy_from_slice(&self.body);
        out
    }

    /// Parse with version + reserved-zero checks.
    ///
    /// Structural checks only (version byte); field semantics (coefficient
    /// ranges, reserved regions) are enforced by the verifier, never here.
    ///
    /// # Errors
    /// * [`Error::MalformedEncoding`] on version mismatch.
    pub fn from_bytes(b: &[u8; PROOF_BYTES]) -> Result<Self> {
        if b[0] != PROOF_VERSION {
            return Err(Error::MalformedEncoding);
        }
        let mut body: [u8; PROOF_BYTES - 1] = [0; PROOF_BYTES - 1];
        body.copy_from_slice(&b[1..]);
        Ok(Self {
            version: b[0],
            body,
        })
    }

    /// Parse from a variable-length slice (transport framing entry point).
    ///
    /// Truncated, overlong, and empty inputs are rejected here so callers
    /// never slice attacker-controlled buffers themselves.
    ///
    /// # Errors
    /// * [`Error::MalformedEncoding`] if `raw.len() != PROOF_BYTES` or the
    ///   version byte mismatches.
    pub fn from_slice(raw: &[u8]) -> Result<Self> {
        if raw.len() != PROOF_BYTES {
            return Err(Error::MalformedEncoding);
        }
        let mut fixed: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        fixed.copy_from_slice(raw);
        Self::from_bytes(&fixed)
    }
}

/// Encode one polynomial as 256 LE bytes (coefficients `< Q` by construction).
pub fn encode_poly(p: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), NCOEFFS * 4);
    for (k, c) in p.iter().enumerate() {
        out[k * 4..k * 4 + 4].copy_from_slice(&c.to_le_bytes());
    }
}

/// Decode one polynomial, enforcing canonical coefficients `< Q`.
///
/// # Errors
/// * [`Error::MalformedEncoding`] if any coefficient is `>= Q`.
pub fn decode_poly(raw: &[u8]) -> Result<Poly> {
    use crate::params::Q;
    if raw.len() != NCOEFFS * 4 {
        return Err(Error::MalformedEncoding);
    }
    let mut p: Poly = [0; NCOEFFS];
    for k in 0..NCOEFFS {
        let mut b: [u8; 4] = [0; 4];
        b.copy_from_slice(&raw[k * 4..k * 4 + 4]);
        let v: u32 = u32::from_le_bytes(b);
        if v >= Q {
            return Err(Error::MalformedEncoding);
        }
        p[k] = v;
    }
    Ok(p)
}

/// Encode a `u32` scalar LE.
pub fn encode_u32(v: u32, out: &mut [u8]) {
    out[..4].copy_from_slice(&v.to_le_bytes());
}

/// Decode a `u32` scalar LE (any value accepted; range checks are the
/// verifier's job per-field).
///
/// # Errors
/// * [`Error::MalformedEncoding`] if `raw.len() != 4`.
pub fn decode_u32(raw: &[u8]) -> Result<u32> {
    if raw.len() != 4 {
        return Err(Error::MalformedEncoding);
    }
    let mut b: [u8; 4] = [0; 4];
    b.copy_from_slice(raw);
    Ok(u32::from_le_bytes(b))
}

/// Pack 8 response polys into [`Z_PACKED_BYTES`] bytes (v2, S2).
///
/// Each coefficient must satisfy `|centered| ≤ RESP_BOUND`; values are
/// stored offset-binary (`centered + 65536`) at 17 bits LSB-first,
/// coeff-major. Exactly `512 × 17 = 8704` bits — no padding bits, so no
/// reserved-bit ambiguity. Branchless over the coefficient values
/// (prover-side secrets); out-of-range inputs fail closed.
///
/// # Errors
/// * [`Error::InvalidParams`] if any coefficient is a field element outside
///   `±RESP_BOUND`, or `out.len() != Z_PACKED_BYTES`. (Non-field inputs
///   `≥ Q` are a caller bug: debug-asserted; release encodes them to words
///   the decoder range-checks, so verification still fails closed.)
pub fn encode_z_packed(z: &[Poly; M_COLS], out: &mut [u8]) -> Result<()> {
    use crate::params::{Q, RESP_BOUND, Z_PACKED_BYTES, Z_PACK_MAX, Z_PACK_MIN};
    // Offset base `Q - 65536`: upper-range coefficients subtract it.
    // (Item first in the body: `items_after_statements` lint.)
    const NEG_BASE: u32 = 1_073_750_017 - 65_536;
    if out.len() != Z_PACKED_BYTES {
        return Err(Error::InvalidParams);
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut pos: usize = 0;
    for poly in z {
        for c in poly {
            // Classify without branches: `small` iff `c ≤ RESP_BOUND`,
            // `big` iff `c ≥ Q − RESP_BOUND`; exactly one holds on valid
            // input (total function: wrapping arithmetic, then Err below).
            let small: u32 = (c.wrapping_sub(RESP_BOUND + 1) >> 31) & 1;
            let t: u32 = (Q - 1).wrapping_sub(*c);
            let big: u32 = (t.wrapping_sub(RESP_BOUND) >> 31) & 1;
            if small | big == 0 {
                return Err(Error::InvalidParams);
            }
            let e: u32 = small
                .wrapping_mul(c.wrapping_add(65_536))
                .wrapping_add(big.wrapping_mul(c.wrapping_sub(NEG_BASE)));
            // `e` is exactly 17 bits on valid input; mask defensively so a
            // caller bug cannot desynchronize the bit stream (decode then
            // rejects via the range check — fail closed, never desync).
            let word: u32 = e & 0x1FFFF;
            debug_assert!((Z_PACK_MIN..=Z_PACK_MAX).contains(&word));
            acc |= word << bits;
            bits += 17;
            while bits >= 8 {
                out[pos] = acc as u8;
                acc >>= 8;
                bits -= 8;
                pos += 1;
            }
        }
    }
    debug_assert_eq!(pos, Z_PACKED_BYTES);
    debug_assert_eq!(bits, 0);
    Ok(())
}

/// Unpack [`Z_PACKED_BYTES`] bytes into 8 response polys (v2, S2).
///
/// Single range check per 17-bit word: reject outside
/// `[Z_PACK_MIN, Z_PACK_MAX]` (canonicality + response bound together).
/// Verifier-side input is public, so plain branches are fine.
///
/// # Errors
/// * [`Error::MalformedEncoding`] on length mismatch or any non-canonical
///   word.
pub fn decode_z_packed(raw: &[u8]) -> Result<[Poly; M_COLS]> {
    use crate::params::{Q, Z_PACKED_BYTES, Z_PACK_MAX, Z_PACK_MIN};
    if raw.len() != Z_PACKED_BYTES {
        return Err(Error::MalformedEncoding);
    }
    let mut out: [Poly; M_COLS] = [[0; NCOEFFS]; M_COLS];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut pos: usize = 0;
    for poly in &mut out {
        for c in poly.iter_mut() {
            while bits < 17 {
                acc |= u32::from(raw[pos]) << bits;
                bits += 8;
                pos += 1;
            }
            let word: u32 = acc & 0x1FFFF;
            acc >>= 17;
            bits -= 17;
            if !(Z_PACK_MIN..=Z_PACK_MAX).contains(&word) {
                return Err(Error::MalformedEncoding);
            }
            // Offset-binary back to mod-`Q` representative (`as` casts exact
            // in the checked range; crate-level truncation allow applies).
            let centered: i64 = i64::from(word) - 65_536;
            *c = if centered < 0 {
                Q - (-centered) as u32
            } else {
                centered as u32
            };
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::{Proof, PROOF_BYTES, PROOF_VERSION};

    #[test]
    fn roundtrip_and_size() {
        assert!(PROOF_BYTES <= 10_240 && PROOF_BYTES >= 2048);
        let p: Proof = Proof {
            version: PROOF_VERSION,
            body: [7; PROOF_BYTES - 1],
        };
        let raw: [u8; PROOF_BYTES] = p.to_bytes();
        assert_eq!(Proof::from_bytes(&raw).expect("parse"), p);
    }

    #[test]
    fn bad_version_rejected() {
        let mut raw: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        raw[0] = PROOF_VERSION.wrapping_add(1);
        assert!(Proof::from_bytes(&raw).is_err());
    }

    #[test]
    fn v1_legacy_rejected_at_cutover() {
        // v1 (6497 B, unpacked) proofs stop verifying at the v2 cutover:
        // even the version byte alone no longer parses (1 != 2).
        let mut raw: [u8; PROOF_BYTES] = [0; PROOF_BYTES];
        raw[0] = 1;
        assert!(Proof::from_bytes(&raw).is_err());
    }

    #[test]
    fn z_pack_roundtrip_edges() {
        use super::{decode_z_packed, encode_z_packed};
        use crate::params::{Q, RESP_BOUND, Z_PACKED_BYTES};
        // Edge centered values: ±bound, ±1, 0.
        for v in [
            -(i64::from(RESP_BOUND)),
            -(i64::from(RESP_BOUND)) + 1,
            -1,
            0,
            1,
            i64::from(RESP_BOUND) - 1,
            i64::from(RESP_BOUND),
        ] {
            let c: u32 = if v < 0 { Q - (-v) as u32 } else { v as u32 };
            let z: [[u32; 64]; 8] = [[c; 64]; 8];
            let mut out: [u8; Z_PACKED_BYTES] = [0; Z_PACKED_BYTES];
            encode_z_packed(&z, &mut out).expect("valid edge");
            assert_eq!(decode_z_packed(&out).expect("decode"), z);
        }
        // Out-of-range field values fail closed at encode time.
        for c in [RESP_BOUND + 1, Q - RESP_BOUND - 1, Q / 2] {
            let z: [[u32; 64]; 8] = [[c; 64]; 8];
            let mut out: [u8; Z_PACKED_BYTES] = [0; Z_PACKED_BYTES];
            assert!(encode_z_packed(&z, &mut out).is_err());
        }
    }

    /// Exhaustive canonicality: every 17-bit word decodes iff it lies in
    /// `[Z_PACK_MIN, Z_PACK_MAX]` (131072 cases, each pinned exactly).
    /// Under Miri the interior is sampled (every 256th word) while all six
    /// boundary words stay exhaustive — full sweep runs in normal CI.
    #[test]
    fn z_pack_exhaustive_words() {
        use super::{decode_z_packed, encode_z_packed};
        use crate::params::{Z_PACKED_BYTES, Z_PACK_MAX, Z_PACK_MIN};
        // One full valid block to mutate word-by-word.
        let z0: [[u32; 64]; 8] = [[0; 64]; 8];
        let mut base: [u8; Z_PACKED_BYTES] = [0; Z_PACKED_BYTES];
        encode_z_packed(&z0, &mut base).expect("zero valid");
        let check = |w: u32| {
            // Splice word `w` into position 0 (bits 0..17: bytes 0,1 and
            // bit 0 of byte 2; bits 1..7 of byte 2 belong to word 1).
            let mut raw: [u8; Z_PACKED_BYTES] = base;
            raw[0] = w as u8;
            raw[1] = (w >> 8) as u8;
            raw[2] = (raw[2] & 0xFE) | ((w >> 16) & 1) as u8;
            let ok: bool = (Z_PACK_MIN..=Z_PACK_MAX).contains(&w);
            assert_eq!(decode_z_packed(&raw).is_ok(), ok, "word {w}");
        };
        // Boundaries always exhaustive (both valid edges and invalid neighbors).
        for w in [0, 63, 64, 65, 131_007, 131_008, 131_009, 131_071] {
            check(w);
        }
        if cfg!(miri) {
            let mut w: u32 = 0;
            while w < 131_072 {
                check(w);
                w += 256;
            }
        } else {
            for w in 0..131_072u32 {
                check(w);
            }
        }
    }
}
