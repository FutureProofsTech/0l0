// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Tiny-model extractor gate (Q1): shells out to `tools/tiny_model.py`.
//!
//! Machine-local gate (requires `python3` on `PATH`; this PC guarantees it).
//! Pins the extraction properties, not exact counts:
//! invertibility is usable (`>= 400/552`), extraction is total over usable
//! pairs (`extracted == invertible`), direct grinding accepts nothing.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::many_single_char_names)]

use std::process::Command;

fn run_model() -> String {
    let out: std::process::Output = Command::new("python3")
        .arg("tools/tiny_model.py")
        .output()
        .expect("python3 must run tools/tiny_model.py on this PC");
    assert!(out.status.success(), "tiny model failed");
    String::from_utf8(out.stdout).expect("utf8 report")
}

fn result_line(report: &str) -> (u32, u32, u32, u32, u32, u32) {
    let line: &str = report
        .lines()
        .find(|l| l.starts_with("RESULT "))
        .expect("RESULT line");
    // RESULT invert=A/B extracted=C/D grind=E/F
    let nums: Vec<u32> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("ints"))
        .collect();
    assert_eq!(nums.len(), 6, "six counters");
    (nums[0], nums[1], nums[2], nums[3], nums[4], nums[5])
}

#[test]
fn tiny_extraction_total() {
    let report: String = run_model();
    let (inv, total, ext, inv2, grind, trials): (u32, u32, u32, u32, u32, u32) =
        result_line(&report);
    assert_eq!(total, 552, "24 challenges -> 552 ordered pairs");
    assert_eq!(inv, inv2, "consistent denominators");
    assert_eq!(trials, 2400);
    assert!(inv >= 400, "rewind-usable pairs {inv}/{total}");
    // THE packing closure, exhibited: every usable pair extracts a witness
    // satisfying BOTH the linear claim and the exact packing scalar.
    assert_eq!(ext, inv, "extraction must be total over usable pairs");
    // Direct grinding: 8 equations over Z_17 per trial -> expect 0 accepts.
    assert_eq!(grind, 0, "no random trial may satisfy 8 equations");
}
