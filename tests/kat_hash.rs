// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Official BLAKE3 KATs re-run in `0l0` (P3 gate).
//! Source: BLAKE3 team `test_vectors.json` (`input[i] = (i % 251) as u8`).

#![allow(clippy::missing_panics_doc)]

use core::fmt::Write as _;
use sq_pq::hash::{hash, xof_into};

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from(i % 251).expect("pattern < 251"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    let mut s: String = String::new();
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn kat_all_official() {
    let cases: [(usize, &str); 11] = [
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            2,
            "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        ),
        (
            31,
            "bda80c7fe2db38be6387b35c870bd7728d67b7b6cc5eb9b0e5c7dcb21ea754c2",
        ),
        (
            32,
            "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65",
        ),
        (
            63,
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        ),
        (
            64,
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        ),
        (
            65,
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
    ];
    for (n, want) in cases {
        assert_eq!(hex(&hash(&pattern(n))), want, "official vector n={n}");
    }
}

#[test]
fn xof_domain_separation_and_determinism() {
    let mut o1: [u8; 64] = [0; 64];
    let mut o2: [u8; 64] = [0; 64];
    let mut o3: [u8; 64] = [0; 64];
    xof_into(b"same-input", 0x01, &mut o1).expect("xof");
    xof_into(b"same-input", 0x02, &mut o2).expect("xof");
    xof_into(b"same-input", 0x01, &mut o3).expect("xof");
    assert_ne!(o1, o2);
    assert_eq!(o1, o3);
}

#[test]
fn hash_bitflip_sensitivity() {
    let a: Vec<u8> = pattern(128);
    let mut b: Vec<u8> = a.clone();
    b[64] ^= 1;
    assert_ne!(hash(&a), hash(&b));
}
