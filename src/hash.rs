// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! BLAKE3 from scratch: portable compression + stack-only one-shot hash.
//!
//! Zero dependencies, `#![forbid(unsafe_code)]`, `no_std` compatible.
//! Same validated design as the `zero-sq` crate (official compression
//! function, 7 rounds, chunk/parent tree); re-implemented here so `sq-pq`
//! stays a zero-dependency monolith. 32-byte [`hash`] is spec-exact against
//! the official test vectors (`input[i] = (i % 251) as u8`).
//!
//! XOF note (honest deviation): extended output uses a documented
//! counter-cascade over [`hash`], not the official `compress_xof` seekable
//! mode. 32-byte [`hash`] itself matches the reference bitwise.

use crate::error::{Error, Result};

/// Block length in bytes.
pub const BLOCK_LEN: usize = 64;
/// Chunk length in bytes.
pub const CHUNK_LEN: usize = 1024;
/// Default output length.
pub const OUT_LEN: usize = 32;
/// Max input supported by one-shot [`hash`] (32 chunks = 32 KiB, stack-only).
pub const MAX_INPUT_LEN: usize = 32 * CHUNK_LEN;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;

#[inline]
const fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline]
fn compress_inner(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut s: [u32; 16] = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        (counter & 0xFFFF_FFFF) as u32,
        ((counter >> 32) & 0xFFFF_FFFF) as u32,
        block_len,
        flags,
    ];
    for r in 0..7 {
        let sched: [usize; 16] = MSG_SCHEDULE[r];
        g(
            &mut s,
            0,
            4,
            8,
            12,
            block_words[sched[0]],
            block_words[sched[1]],
        );
        g(
            &mut s,
            1,
            5,
            9,
            13,
            block_words[sched[2]],
            block_words[sched[3]],
        );
        g(
            &mut s,
            2,
            6,
            10,
            14,
            block_words[sched[4]],
            block_words[sched[5]],
        );
        g(
            &mut s,
            3,
            7,
            11,
            15,
            block_words[sched[6]],
            block_words[sched[7]],
        );
        g(
            &mut s,
            0,
            5,
            10,
            15,
            block_words[sched[8]],
            block_words[sched[9]],
        );
        g(
            &mut s,
            1,
            6,
            11,
            12,
            block_words[sched[10]],
            block_words[sched[11]],
        );
        g(
            &mut s,
            2,
            7,
            8,
            13,
            block_words[sched[12]],
            block_words[sched[13]],
        );
        g(
            &mut s,
            3,
            4,
            9,
            14,
            block_words[sched[14]],
            block_words[sched[15]],
        );
    }
    s
}

fn block_words_from_bytes(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut w: [u32; 16] = [0; 16];
    for (i, slot) in w.iter_mut().enumerate() {
        let o: usize = i * 4;
        *slot = u32::from_le_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
    }
    w
}

fn words_to_le_bytes8(cv: &[u32; 8]) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for (i, v) in cv.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// Raw compression returning full 16-word state post-mix (pre-feedforward).
fn compress_full(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let w: [u32; 16] = block_words_from_bytes(block);
    compress_inner(cv, &w, counter, block_len, flags)
}

/// Chaining value (first 8 words, feedforward `s[i]^s[i+8]`).
fn compress_cv(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 8] {
    let s: [u32; 16] = compress_full(cv, block, counter, block_len, flags);
    [
        s[0] ^ s[8],
        s[1] ^ s[9],
        s[2] ^ s[10],
        s[3] ^ s[11],
        s[4] ^ s[12],
        s[5] ^ s[13],
        s[6] ^ s[14],
        s[7] ^ s[15],
    ]
}

/// Compute chunk chaining value (no `ROOT` flag).
fn chunk_cv(chunk: &[u8], chunk_counter: u64) -> [u8; 32] {
    debug_assert!(!chunk.is_empty() && chunk.len() <= CHUNK_LEN);
    let mut cv: [u32; 8] = IV;
    let num_blocks: usize = chunk.len().div_ceil(BLOCK_LEN);
    for (i, block_slice) in chunk.chunks(BLOCK_LEN).enumerate() {
        let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
        block[..block_slice.len()].copy_from_slice(block_slice);
        let mut flags: u32 = 0;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i == num_blocks - 1 {
            flags |= CHUNK_END;
        }
        let out: [u32; 8] = compress_cv(
            &cv,
            &block,
            chunk_counter,
            u32::try_from(block_slice.len()).expect("block <= 64"),
            flags,
        );
        cv = out;
    }
    words_to_le_bytes8(&cv)
}

/// Single-chunk root hash (last block carries `ROOT`).
fn single_chunk_root(chunk: &[u8]) -> [u8; 32] {
    debug_assert!(chunk.len() <= CHUNK_LEN);
    if chunk.is_empty() {
        let block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
        let cv: [u32; 8] = compress_cv(&IV, &block, 0, 0, CHUNK_START | CHUNK_END | ROOT);
        return words_to_le_bytes8(&cv);
    }
    let mut cv: [u32; 8] = IV;
    let num_blocks: usize = chunk.len().div_ceil(BLOCK_LEN);
    for (i, block_slice) in chunk.chunks(BLOCK_LEN).enumerate() {
        let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
        block[..block_slice.len()].copy_from_slice(block_slice);
        let mut flags: u32 = 0;
        if i == 0 {
            flags |= CHUNK_START;
        }
        let last: bool = i == num_blocks - 1;
        if last {
            flags |= CHUNK_END | ROOT;
        }
        let out: [u32; 8] = compress_cv(
            &cv,
            &block,
            0,
            u32::try_from(block_slice.len()).expect("block <= 64"),
            flags,
        );
        cv = out;
    }
    words_to_le_bytes8(&cv)
}

fn parent_cv_raw(left: &[u8; 32], right: &[u8; 32], is_root: bool) -> [u8; 32] {
    let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    let flags: u32 = if is_root { PARENT | ROOT } else { PARENT };
    let cv: [u32; 8] = compress_cv(
        &IV,
        &block,
        0,
        u32::try_from(BLOCK_LEN).expect("const 64"),
        flags,
    );
    words_to_le_bytes8(&cv)
}

/// One-shot BLAKE3 32-byte hash, stack-only, supports `0..=MAX_INPUT_LEN` bytes.
///
/// # Panics
/// Panics via `expect` in all profiles if input exceeds [`MAX_INPUT_LEN`]
/// (no silent truncation). Use [`try_hash`] for the fallible API.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    try_hash(data).expect("blake3 input too long")
}

/// Fallible one-shot hash.
///
/// # Errors
/// * [`Error::InputTooLong`] if `data.len() > MAX_INPUT_LEN`.
///
/// # Panics
/// Never panics in practice: the chunk counter `i` stays below 32
/// (`MAX_INPUT_LEN` bounds the chunk count); the `expect` is unreachable.
pub fn try_hash(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() > MAX_INPUT_LEN {
        return Err(Error::InputTooLong);
    }
    if data.len() <= CHUNK_LEN {
        return Ok(single_chunk_root(data));
    }
    // Multi-chunk: collect chunk CVs on stack (max 32), then collapse.
    // Pairwise with odd-carry: `m = ceil(n/2)` per level, so `m == 1`
    // implies the previous `n == 2` and the single parent already carries
    // `ROOT` — no extra finalization step is needed.
    let num_chunks: usize = data.len().div_ceil(CHUNK_LEN);
    let mut cvs: [[u8; 32]; 32] = [[0; 32]; 32];
    for (i, chunk) in data.chunks(CHUNK_LEN).enumerate() {
        cvs[i] = chunk_cv(chunk, u64::try_from(i).expect("chunk count < 32"));
    }
    let mut n: usize = num_chunks;
    let mut buf: [[u8; 32]; 32] = [[0; 32]; 32];
    while n > 1 {
        let mut m: usize = 0;
        let mut i: usize = 0;
        while i < n {
            if i + 1 < n {
                let is_root: bool = n == 2 && m == 0;
                buf[m] = parent_cv_raw(&cvs[i], &cvs[i + 1], is_root);
                m += 1;
                i += 2;
            } else {
                buf[m] = cvs[i];
                m += 1;
                i += 1;
            }
        }
        cvs[..m].copy_from_slice(&buf[..m]);
        n = m;
    }
    Ok(cvs[0])
}

/// Documented counter-cascade XOF built on [`hash`].
///
/// `out` is filled from `hash` blocks over `input ‖ tag ‖ LE64(counter)`
/// (short inputs) or a digested preimage (long inputs) — see body.
/// `domain_tag` separates transcript domains. Stack-only; `out.len()<=2048`.
///
/// # Errors
/// * [`Error::InputTooLong`] if `out.len() > 2048`.
pub fn xof_into(input: &[u8], domain_tag: u8, out: &mut [u8]) -> Result<()> {
    if out.len() > 2048 {
        return Err(Error::InputTooLong);
    }
    let short: bool = input.len() <= 256;
    let mut ctr: u64 = 0;
    let mut pos: usize = 0;
    if short {
        let mut buf: [u8; 256 + 1 + 8] = [0; 265];
        buf[..input.len()].copy_from_slice(input);
        while pos < out.len() {
            let base: usize = input.len();
            buf[base] = domain_tag;
            buf[base + 1..base + 9].copy_from_slice(&ctr.to_le_bytes());
            let total: usize = base + 9;
            let digest: [u8; 32] = hash(&buf[..total]);
            let take: usize = core::cmp::min(32, out.len() - pos);
            out[pos..pos + take].copy_from_slice(&digest[..take]);
            pos += take;
            ctr += 1;
        }
    } else {
        // Long input: compress to a digest first (domain-separated).
        let mut pre: [u8; 33] = [0; 33];
        let d: [u8; 32] = hash(input);
        pre[..32].copy_from_slice(&d);
        pre[32] = domain_tag;
        let pred: [u8; 32] = hash(&pre);
        let mut buf2: [u8; 41] = [0; 41];
        buf2[..32].copy_from_slice(&pred);
        while pos < out.len() {
            buf2[32] = domain_tag;
            buf2[33..41].copy_from_slice(&ctr.to_le_bytes());
            let digest: [u8; 32] = hash(&buf2);
            let take: usize = core::cmp::min(32, out.len() - pos);
            out[pos..pos + take].copy_from_slice(&digest[..take]);
            pos += take;
            ctr += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::hash;
    use core::fmt::Write as _;

    fn pattern(n: usize) -> std::vec::Vec<u8> {
        (0..n)
            .map(|i: usize| u8::try_from(i % 251).expect("test pattern < 251"))
            .collect()
    }

    fn hex(b: &[u8]) -> std::string::String {
        let mut s: std::string::String = std::string::String::new();
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    #[test]
    fn empty_kat() {
        let h: [u8; 32] = hash(&[]);
        assert_eq!(
            hex(&h),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn small_kats() {
        let cases: [(usize, &str); 6] = [
            (
                1,
                "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            ),
            (
                2,
                "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
            ),
            (
                32,
                "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65",
            ),
            (
                64,
                "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
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
            let input: std::vec::Vec<u8> = pattern(n);
            assert_eq!(hex(&hash(&input)), want, "n={n}");
        }
    }
}
