// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Fiat-Shamir transcript over BLAKE3 (stack-only, canonical LE encoding).
//!
//! Domain separation tags are single bytes mixed into the XOF stage.
//! Every absorption binds `(label || len_le16 || data)` into a 32-byte chain:
//! `state = hash(state || label || len || data)`. Challenges are squeezed via
//! [`crate::hash::xof_into`] with distinct tags, so omitting any field changes
//! all downstream challenges (red-team mutation tests).

use crate::error::{Error, Result};
use crate::hash as blake3;

/// Round-challenge domain (v0.1 challenge seeds; reused by the JL
/// aggregation follow-up).
pub const TAG_PROJ: u8 = 0x50;
/// Blinding domain (rejection-sampling salt derivation).
pub const TAG_BLIND: u8 = 0x42;

/// Fixed transcript: 32-byte chain state, no heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    /// New transcript from a domain string (hashed to 32 B, stack-only).
    #[must_use]
    pub fn new(domain: &[u8]) -> Self {
        Self {
            state: blake3::hash(domain),
        }
    }

    /// Absorb `(label || data)` with a canonical length prefix.
    ///
    /// # Errors
    /// * [`Error::TranscriptError`] if `label.len() > 64` or `data.len() > 2048`.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) -> Result<()> {
        if label.len() > 64 || data.len() > 2048 {
            return Err(Error::TranscriptError);
        }
        let len16: u16 = u16::try_from(data.len()).map_err(|_| Error::TranscriptError)?;
        // Fixed scratch sized for the short path; long data is digested first
        // so the stack frame stays bounded either way.
        let (staging, staged_len): ([u8; 1122], usize) = if data.len() <= 1024 {
            let mut buf: [u8; 32 + 64 + 2 + 1024] = [0; 1122];
            buf[..32].copy_from_slice(&self.state);
            buf[32..32 + label.len()].copy_from_slice(label);
            let lb: usize = 32 + label.len();
            buf[lb..lb + 2].copy_from_slice(&len16.to_le_bytes());
            buf[lb + 2..lb + 2 + data.len()].copy_from_slice(data);
            (buf, lb + 2 + data.len())
        } else {
            let d: [u8; 32] = blake3::hash(data);
            let mut buf: [u8; 32 + 64 + 2 + 1024] = [0; 1122];
            buf[..32].copy_from_slice(&self.state);
            buf[32..32 + label.len()].copy_from_slice(label);
            let lb: usize = 32 + label.len();
            buf[lb..lb + 2].copy_from_slice(&len16.to_le_bytes());
            buf[lb + 2..lb + 34].copy_from_slice(&d);
            (buf, lb + 34)
        };
        self.state = blake3::hash(&staging[..staged_len]);
        Ok(())
    }

    /// Squeeze `out.len()` bytes under `tag`.
    ///
    /// # Errors
    /// * Propagates [`blake3::xof_into`] length errors.
    pub fn squeeze(&self, tag: u8, out: &mut [u8]) -> Result<()> {
        blake3::xof_into(&self.state, tag, out)
    }

    /// Squeeze a 32-byte challenge.
    ///
    /// # Errors
    /// * Propagates [`blake3::xof_into`] length errors (unreachable for 32 B).
    pub fn challenge32(&self, tag: u8) -> Result<[u8; 32]> {
        let mut out: [u8; 32] = [0; 32];
        self.squeeze(tag, &mut out)?;
        Ok(out)
    }

    /// Current chain bytes.
    #[must_use]
    pub const fn state(&self) -> [u8; 32] {
        self.state
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new(b"sq-pq/v0.1")
    }
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::{Transcript, TAG_PROJ};

    #[test]
    fn absorb_is_binding() {
        let mut a: Transcript = Transcript::new(b"sq-pq/v0.1");
        let mut b: Transcript = Transcript::new(b"sq-pq/v0.1");
        a.absorb(b"root", &[1, 2, 3]).expect("absorb");
        b.absorb(b"root", &[1, 2, 4]).expect("absorb");
        assert_ne!(a.state(), b.state());
    }

    #[test]
    fn label_matters() {
        let mut a: Transcript = Transcript::new(b"sq-pq/v0.1");
        let mut b: Transcript = Transcript::new(b"sq-pq/v0.1");
        a.absorb(b"a", b"data").expect("absorb");
        b.absorb(b"b", b"data").expect("absorb");
        assert_ne!(
            a.challenge32(TAG_PROJ).expect("challenge"),
            b.challenge32(TAG_PROJ).expect("challenge")
        );
    }

    #[test]
    fn drop_field_changes_challenge() {
        let mut full: Transcript = Transcript::new(b"sq-pq/v0.1");
        full.absorb(b"y", &[1; 32]).expect("absorb");
        full.absorb(b"root", &[2; 32]).expect("absorb");
        let c_full: [u8; 32] = full.challenge32(TAG_PROJ).expect("challenge");
        let mut dropped: Transcript = Transcript::new(b"sq-pq/v0.1");
        dropped.absorb(b"y", &[1; 32]).expect("absorb");
        let c_dropped: [u8; 32] = dropped.challenge32(TAG_PROJ).expect("challenge");
        assert_ne!(c_full, c_dropped);
    }
}
