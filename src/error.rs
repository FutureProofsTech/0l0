// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Fixed error type. No heap, no `String`, no `std::error::Error` in `no_std`.

use core::fmt::{Display, Formatter, Result as FmtResult};

/// All fallible operations in `sq-pq` return this fixed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// Witness does not satisfy the relation `R*`.
    UnsatisfiedRelation,
    /// Committed opening failed (binding or norm check).
    OpeningFailed,
    /// Norm bound exceeded (`‖w‖_∞ > β` or `‖w‖_2 > B`).
    NormExceeded,
    /// Proof failed verification (binding, challenge, or encoding).
    VerificationFailed,
    /// Malformed encoding (non-canonical, out of range, truncated, bad version).
    MalformedEncoding,
    /// Transcript misuse (bad label length, oversize input).
    TranscriptError,
    /// Input too long for the fixed stack buffers.
    InputTooLong,
    /// Invalid parameters (internal bug).
    InvalidParams,
    /// Rejection sampling exhausted its fixed retry budget (prover must retry
    /// with fresh salt; verifier never sees this).
    SamplingExhausted,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let s: &str = match self {
            Self::UnsatisfiedRelation => "unsatisfied relation",
            Self::OpeningFailed => "opening failed",
            Self::NormExceeded => "norm exceeded",
            Self::VerificationFailed => "verification failed",
            Self::MalformedEncoding => "malformed encoding",
            Self::TranscriptError => "transcript error",
            Self::InputTooLong => "input too long",
            Self::InvalidParams => "invalid params",
            Self::SamplingExhausted => "sampling exhausted",
        };
        f.write_str(s)
    }
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, Error>;
