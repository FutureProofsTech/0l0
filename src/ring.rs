// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 0l0 contributors. See LICENSE.

//! Ring arithmetic over `R_q = Z_q[X]/(X^D + 1)` (P1: `Z_q` + naive products
//! real; NTT lands in P2).
//!
//! All operations are stack-only with `u64` intermediates (products of two
//! `< q` values fit: `(2^30)^2 < 2^64`). Coefficient casts are bounded by
//! construction (`< Q <= u32::MAX`).

use crate::params::{D, Q};

/// Primitive 64-th root of unity: `5^((Q-1)/64) mod Q` (verified order 64:
/// `W64^64 = 1`, `W64^32 = Q-1 ≠ 1`; see P2 discovery log in results).
pub const W64: u32 = 817_737_403;
/// `W64^{-1} = W64^63 mod Q`.
pub const W64_INV: u32 = 678_067_437;
/// Primitive 128-th root with `PSI128^2 = W64` (NWC twist).
pub const PSI128: u32 = 187_094_501;
/// `PSI128^{-1} = PSI128^127 mod Q`.
pub const PSI128_INV: u32 = 441_327_809;
/// `64^{-1} mod Q` for the inverse transform scale.
pub const N_INV64: u32 = 1_056_972_673;

/// Powers `PSI128^j` (forward twist), computed at compile time.
pub const PSI_POW: [u32; NCOEFFS] = {
    let mut t: [u32; NCOEFFS] = [0; NCOEFFS];
    let mut p: u32 = 1;
    let mut i: usize = 0;
    while i < NCOEFFS {
        t[i] = p;
        p = mul_mod_u32(p, PSI128);
        i += 1;
    }
    t
};

/// Powers `PSI128^{-j}` (inverse twist), computed at compile time.
pub const PSI_INV_POW: [u32; NCOEFFS] = {
    let mut t: [u32; NCOEFFS] = [0; NCOEFFS];
    let mut p: u32 = 1;
    let mut i: usize = 0;
    while i < NCOEFFS {
        t[i] = p;
        p = mul_mod_u32(p, PSI128_INV);
        i += 1;
    }
    t
};

/// 6-bit reversal for the size-64 decimation-in-time NTT.
#[must_use]
pub const fn bitrev6(x: usize) -> usize {
    let mut r: usize = 0;
    let mut b: usize = x & 63;
    let mut i: usize = 0;
    while i < 6 {
        r = (r << 1) | (b & 1);
        b >>= 1;
        i += 1;
    }
    r
}

/// Iterative radix-2 cyclic NTT core with the given primitive root.
///
/// Fixed bounds (`6` stages), `u64` intermediates, no data branches.
#[must_use]
pub fn ntt_core(a: &Poly, root: u32) -> Poly {
    let mut t: Poly = [0; NCOEFFS];
    for i in 0..NCOEFFS {
        t[i] = a[bitrev6(i)];
    }
    let mut len: usize = 1;
    while len < NCOEFFS {
        // `wlen = root^(64 / (2*len))` by fixed-step repeated multiplication.
        let e: usize = NCOEFFS / (2 * len);
        let mut wlen: u32 = 1;
        let mut j: usize = 0;
        while j < e {
            wlen = mul_mod_u32(wlen, root);
            j += 1;
        }
        let mut i: usize = 0;
        while i < NCOEFFS {
            let mut w: u32 = 1;
            let mut j: usize = 0;
            while j < len {
                let u: u32 = t[i + j];
                let v: u32 = mul_mod_u32(t[i + j + len], w);
                t[i + j] = add_mod(u, v);
                t[i + j + len] = sub_mod(u, v);
                w = mul_mod_u32(w, wlen);
                j += 1;
            }
            i += 2 * len;
        }
        len *= 2;
    }
    t
}

/// Number of coefficients per polynomial (== [`D`]).
pub const NCOEFFS: usize = D;

/// Polynomial in coefficient form (values always reduced `< Q`).
pub type Poly = [u32; NCOEFFS];

/// Modular addition.
#[inline]
#[must_use]
pub const fn add_mod(a: u32, b: u32) -> u32 {
    let s: u32 = a + b;
    if s >= Q {
        s - Q
    } else {
        s
    }
}

/// Modular subtraction.
#[inline]
#[must_use]
pub const fn sub_mod(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

/// Modular multiplication (`u64` intermediate, exact).
#[inline]
#[must_use]
pub const fn mul_mod(a: u32, b: u32) -> u64 {
    ((a as u64) * (b as u64)) % (Q as u64)
}

/// Modular multiplication returning reduced `u32` (< Q by construction, so
/// the narrowing cast is lossless).
#[inline]
#[must_use]
pub const fn mul_mod_u32(a: u32, b: u32) -> u32 {
    (mul_mod(a, b)) as u32
}

/// Power by square-and-multiply (fixed 32 steps).
#[must_use]
pub const fn pow_mod(mut base: u32, mut exp: u32) -> u32 {
    let mut res: u32 = 1;
    let mut i: u32 = 0;
    while i < 32 {
        let bit: u32 = exp & 1;
        let mask: u32 = 0u32.wrapping_sub(bit);
        let cand: u32 = mul_mod_u32(res, base);
        res = (cand & mask) | (res & !mask);
        base = mul_mod_u32(base, base);
        exp >>= 1;
        i += 1;
    }
    res
}

/// Inverse via Fermat (`Q` prime). Returns 0 for 0 (documented).
#[must_use]
pub const fn inv_mod(a: u32) -> u32 {
    // Branchless zero-map: Fermat gives 0^…=0 only if we mask; `pow_mod(0,…)=0`
    // already, since all products stay 0. Documented, no secret branches.
    pow_mod(a, Q - 2)
}

/// Coefficient-wise addition.
#[must_use]
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut out: Poly = [0; NCOEFFS];
    for i in 0..NCOEFFS {
        out[i] = add_mod(a[i], b[i]);
    }
    out
}

/// Negacyclic product `c = a*b mod (X^D+1)`, naive `O(D^2)` schoolbook.
///
/// `i128` accumulator is exact: at most `D=64` products of `< Q^2 ≈ 2^60`
/// each fit in `±2^66 << 2^127`. Wrapped terms use `X^D = -1`.
///
/// Correct and auditable; the NTT fast path lands in P2 and must match this
/// bitwise (differential test).
#[must_use]
pub fn poly_mul_naive(a: &Poly, b: &Poly) -> Poly {
    let mut acc: [i128; NCOEFFS] = [0; NCOEFFS];
    for i in 0..NCOEFFS {
        for j in 0..NCOEFFS {
            let p: i128 = i128::from(a[i]) * i128::from(b[j]);
            let k: usize = i + j;
            if k < NCOEFFS {
                acc[k] += p;
            } else {
                // `X^D = -1`: wrap with negation.
                acc[k - NCOEFFS] -= p;
            }
        }
    }
    let mut out: Poly = [0; NCOEFFS];
    let q: i128 = i128::from(Q);
    for i in 0..NCOEFFS {
        let mut r: i128 = acc[i] % q;
        if r < 0 {
            r += q;
        }
        out[i] = r as u32;
    }
    out
}

/// Forward NTT over the cyclic group (size 64, primitive root [`W64`]).
///
/// Replaced by [`poly_mul_nwc`] for ring products; exposed for differential
/// tests and the invertibility check below.
/// Fixed loop bounds, no secret-dependent branches.
#[must_use]
pub fn ntt_forward(a: &Poly) -> Poly {
    ntt_core(a, W64)
}

/// True iff the NWC spectrum of `a` has a zero coefficient, i.e. `a` is NOT
/// invertible in `R_q = Z_q[X]/(X^64+1)` (a zero divisor or zero).
///
/// NOTE: this must use the twisted (NWC) spectrum, not the plain cyclic
/// NTT: `X^64+1` vanishes exactly at the 128-th roots `ζ = ψ·w^k`, and
/// `a` is non-invertible iff it vanishes at one of them. A cyclic-NTT
/// zero test answers the wrong question (`X^64−1`) — and fails
/// systematically on sparse differences, as the red-team run caught.
/// See `docs/extraction.md`.
///
/// Used by the extraction analysis: rewinding extraction divides by
/// challenge differences, which requires invertible `Δc` — measured, not
/// assumed (test below).
#[must_use]
pub fn nwc_has_zero(a: &Poly) -> bool {
    let mut ap: Poly = [0; NCOEFFS];
    for (dst, (x, p)) in ap.iter_mut().zip(a.iter().zip(PSI_POW.iter())) {
        *dst = mul_mod_u32(*x, *p);
    }
    let t: Poly = ntt_forward(&ap);
    for c in &t {
        if *c == 0 {
            return true;
        }
    }
    false
}

/// Inverse NTT (multiplies by `64^{-1}` at the end).
#[must_use]
pub fn ntt_inverse(a: &Poly) -> Poly {
    let mut t: Poly = ntt_core(a, W64_INV);
    for c in &mut t {
        *c = mul_mod_u32(*c, N_INV64);
    }
    t
}

/// Negacyclic product with pre-transformed `c` (S1 hoist).
///
/// `c_ntt` must equal `NTT(twist(c))` (e.g. from [`ntt_forward`] over
/// twisted coefficients); saves re-transforming a fixed multiplicand
/// across many products. Values identical to [`poly_mul_nwc`].
#[must_use]
pub(crate) fn poly_mul_nwc_pre(c_ntt: &Poly, b: &Poly) -> Poly {
    let mut bt: Poly = [0; NCOEFFS];
    for (j, v) in b.iter().enumerate() {
        bt[j] = mul_mod_u32(*v, PSI_POW[j]);
    }
    let bntt: Poly = ntt_forward(&bt);
    let mut cp: Poly = [0; NCOEFFS];
    for (j, (x, y)) in c_ntt.iter().zip(bntt.iter()).enumerate() {
        cp[j] = mul_mod_u32(*x, *y);
    }
    cp = ntt_inverse(&cp);
    let mut out: Poly = [0; NCOEFFS];
    for (j, v) in cp.iter().enumerate() {
        out[j] = mul_mod_u32(*v, PSI_INV_POW[j]);
    }
    out
}

/// Twist + forward transform of one polynomial (hoisting helper).
#[must_use]
pub(crate) fn twist_ntt(p: &Poly) -> Poly {
    let mut tw: Poly = [0; NCOEFFS];
    for (j, v) in p.iter().enumerate() {
        tw[j] = mul_mod_u32(*v, PSI_POW[j]);
    }
    ntt_forward(&tw)
}

/// Negacyclic product via Negative Wrapped Convolution:
/// `c = psi^{-1} · INTT(NTT(psi·a) ⊙ NTT(psi·b))`.
///
/// Must equal [`poly_mul_naive`] bitwise (differential test). Fixed bounds,
/// `u64` intermediates (all values `< 2q`, products `< 2q² < 2^62`).
#[must_use]
pub fn poly_mul_nwc(a: &Poly, b: &Poly) -> Poly {
    let mut ap: Poly = [0; NCOEFFS];
    let mut bp: Poly = [0; NCOEFFS];
    for j in 0..NCOEFFS {
        ap[j] = mul_mod_u32(a[j], PSI_POW[j]);
        bp[j] = mul_mod_u32(b[j], PSI_POW[j]);
    }
    let mut cp: Poly = ntt_forward(&ap);
    let dp: Poly = ntt_forward(&bp);
    for j in 0..NCOEFFS {
        cp[j] = mul_mod_u32(cp[j], dp[j]);
    }
    cp = ntt_inverse(&cp);
    let mut out: Poly = [0; NCOEFFS];
    for j in 0..NCOEFFS {
        out[j] = mul_mod_u32(cp[j], PSI_INV_POW[j]);
    }
    out
}

#[cfg(test)]
#[allow(clippy::missing_panics_doc)]
mod tests {
    use super::{
        add_mod, bitrev6, inv_mod, mul_mod_u32, ntt_forward, ntt_inverse, poly_add, poly_mul_naive,
        poly_mul_nwc, pow_mod, sub_mod, Poly, NCOEFFS, PSI128, PSI128_INV, PSI_POW, Q, W64,
        W64_INV,
    };

    #[test]
    fn zq_basics() {
        assert_eq!(add_mod(Q - 1, 1), 0);
        assert_eq!(sub_mod(0, 1), Q - 1);
        assert_eq!(mul_mod_u32(0, 123), 0);
        assert_eq!(mul_mod_u32(1, 456), 456);
        assert_eq!(inv_mod(0), 0);
        assert_eq!(mul_mod_u32(7, inv_mod(7)), 1);
    }

    #[test]
    fn roots_have_exact_order() {
        // `W64` primitive 64-th root: `w^64 = 1`, `w^32 = -1 ≠ 1`.
        assert_eq!(pow_mod(W64, 64), 1);
        assert_eq!(pow_mod(W64, 32), Q - 1);
        assert_eq!(mul_mod_u32(W64, W64_INV), 1);
        // Twist: `psi^128 = 1`, `psi^2 = w`.
        assert_eq!(pow_mod(PSI128, 128), 1);
        assert_eq!(mul_mod_u32(PSI128, PSI128), W64);
        assert_eq!(mul_mod_u32(PSI128, PSI128_INV), 1);
        // Twist tables consistent with scalar powers.
        assert_eq!(PSI_POW[0], 1);
        assert_eq!(PSI_POW[1], PSI128);
        assert_eq!(PSI_POW[63], pow_mod(PSI128, 63));
    }

    #[test]
    fn bitrev_spot() {
        assert_eq!(bitrev6(0), 0);
        assert_eq!(bitrev6(1), 32);
        assert_eq!(bitrev6(32), 1);
        assert_eq!(bitrev6(63), 63);
        assert_eq!(bitrev6(0b10_1100), 0b00_1101);
    }

    #[test]
    fn poly_mul_identity_and_wrap() {
        let mut one: Poly = [0; NCOEFFS];
        one[0] = 1;
        let mut a: Poly = [0; NCOEFFS];
        for (i, c) in a.iter_mut().enumerate() {
            *c = u32::try_from(i).expect("test index < D");
        }
        assert_eq!(poly_mul_naive(&a, &one), a);
        assert_eq!(poly_mul_nwc(&a, &one), a);
        // `X^63 * X = X^64 = -1`.
        let mut x63: Poly = [0; NCOEFFS];
        x63[63] = 1;
        let mut x: Poly = [0; NCOEFFS];
        x[1] = 1;
        let mut neg_one: Poly = [0; NCOEFFS];
        neg_one[0] = Q - 1;
        assert_eq!(poly_mul_naive(&x63, &x), neg_one);
        assert_eq!(poly_mul_nwc(&x63, &x), neg_one);
    }

    /// Deterministic PRNG (splitmix64) for test vectors — no dependencies.
    fn rng_next(s: &mut u64) -> u64 {
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z: u64 = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn ntt_roundtrip() {
        let mut s: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..16 {
            let mut a: Poly = [0; NCOEFFS];
            for c in &mut a {
                *c = u32::try_from(rng_next(&mut s) % u64::from(Q)).expect("mod q");
            }
            assert_eq!(ntt_inverse(&ntt_forward(&a)), a);
        }
        // Edge: all-max coefficients.
        let max: Poly = [Q - 1; NCOEFFS];
        assert_eq!(ntt_inverse(&ntt_forward(&max)), max);
    }

    #[test]
    fn ntt_linearity() {
        let mut s: u64 = 99;
        let mut a: Poly = [0; NCOEFFS];
        let mut b: Poly = [0; NCOEFFS];
        for i in 0..NCOEFFS {
            a[i] = u32::try_from(rng_next(&mut s) % u64::from(Q)).expect("mod q");
            b[i] = u32::try_from(rng_next(&mut s) % u64::from(Q)).expect("mod q");
        }
        let sum: Poly = poly_add(&a, &b);
        let (fa, fb, fs): (Poly, Poly, Poly) =
            (ntt_forward(&a), ntt_forward(&b), ntt_forward(&sum));
        for i in 0..NCOEFFS {
            assert_eq!(fs[i], add_mod(fa[i], fb[i]));
        }
    }

    #[test]
    fn nwc_matches_naive_differential() {
        let mut s: u64 = 0xDEAD_BEEF_CAFE_0042;
        for _ in 0..64 {
            let mut a: Poly = [0; NCOEFFS];
            let mut b: Poly = [0; NCOEFFS];
            for i in 0..NCOEFFS {
                a[i] = u32::try_from(rng_next(&mut s) % u64::from(Q)).expect("mod q");
                b[i] = u32::try_from(rng_next(&mut s) % u64::from(Q)).expect("mod q");
            }
            assert_eq!(poly_mul_nwc(&a, &b), poly_mul_naive(&a, &b));
        }
        // Overflow catchers: full-range coefficients on both sides.
        let max: Poly = [Q - 1; NCOEFFS];
        assert_eq!(poly_mul_nwc(&max, &max), poly_mul_naive(&max, &max));
        let mut alt: Poly = [0; NCOEFFS];
        for (i, c) in alt.iter_mut().enumerate() {
            *c = if i % 2 == 0 { Q - 1 } else { Q - 2 };
        }
        assert_eq!(poly_mul_nwc(&alt, &max), poly_mul_naive(&alt, &max));
    }

    #[test]
    fn nwc_zero_means_noninvertible() {
        use super::{nwc_has_zero, PSI128};
        assert!(nwc_has_zero(&[0; NCOEFFS]));
        let mut one: Poly = [0; NCOEFFS];
        one[0] = 1;
        assert!(!nwc_has_zero(&one));
        // `X^32` is a unit (`(X^32)·(−X^32) = −X^64 = 1`).
        let mut x32: Poly = [0; NCOEFFS];
        x32[32] = 1;
        assert!(!nwc_has_zero(&x32));
        // `X − ψ` vanishes at NWC slot 0 (`ψ^64 = −1`), hence zero divisor.
        let mut lin: Poly = [0; NCOEFFS];
        lin[0] = Q - PSI128;
        lin[1] = 1;
        assert!(nwc_has_zero(&lin));
    }

    /// Extraction premise, measured: differences of weight-16 ternary
    /// challenges are invertible in `R_q` (no NWC-spectrum zero).
    ///
    /// Heuristic failure is `≈ 64/Q ≈ 2^-24` per difference; over 200 pairs
    /// the expected count is `≈ 1.2e-5`, so a failure here is a genuine
    /// finding about the challenge distribution, not noise. (An earlier
    /// revision tested the *cyclic* spectrum by mistake and failed at pair
    /// 3 — correctly, since weight-2 cyclic differences always vanish; the
    /// negacyclic check is the right question. See `docs/extraction.md`.)
    #[test]
    fn challenge_differences_invertible() {
        use crate::prover::expand_challenge;
        let mut seeds_a: [u8; 32] = [0xC0; 32];
        let mut seeds_b: [u8; 32] = [0x0D; 32];
        for i in 0..200u32 {
            seeds_a[..4].copy_from_slice(&i.to_le_bytes());
            seeds_b[..4].copy_from_slice(&i.wrapping_mul(0x9E37_79B9).to_le_bytes());
            let c1: Poly = expand_challenge(&seeds_a);
            let c2: Poly = expand_challenge(&seeds_b);
            // Determinism premise (same seed, same challenge).
            assert_eq!(c1, expand_challenge(&seeds_a));
            if c1 == c2 {
                continue; // identical challenges carry no extraction info
            }
            let mut diff: Poly = [0; NCOEFFS];
            for (d, (x, y)) in diff.iter_mut().zip(c1.iter().zip(c2.iter())) {
                *d = if x >= y { x - y } else { x + Q - y };
            }
            assert!(
                !super::nwc_has_zero(&diff),
                "non-invertible challenge difference at pair {i}"
            );
        }
    }
}
