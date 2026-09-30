// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Byte-identical differential gate (Q5): Rust vs independent Python model.
//!
//! Machine-local gate (requires `python3`; this PC guarantees it). Runs
//! `tools/diff_vectors.py` (KATs + NTT self-check + 2 byte-identical proofs)
//! and fails on any mismatch or nonzero exit.

#![allow(clippy::missing_panics_doc)]

use std::process::Command;

#[test]
fn python_model_byte_identical() {
    let out: std::process::Output = Command::new("python3")
        .arg("tools/diff_vectors.py")
        .output()
        .expect("python3 must run tools/diff_vectors.py on this PC");
    let log: String =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "differential failed:\n{log}");
    assert!(
        log.contains("byte-identical"),
        "missing differential line:\n{log}"
    );
}
