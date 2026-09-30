#!/usr/bin/env python3
"""Exact hiding numbers for the uniform-mask response (Q3 audit artifact).

Per coefficient: mask uniform on M = 2*S+1 points (S = 65536), shifted by
s = (c*w)_coeff with |s| <= 16 (measured premise, prover test
`challenge_shift_bounded`). Statistical distance per coefficient:
  TV_1 = |s| / M <= 16 / 131073 = 2^-13.00 (exact worst case).
Joint over N = 512 independent coefficients (union bound):
  TV_N <= N * TV_1 = 8192 / 131073 = 0.062499... < 2^-4.
Renyi-2 per coefficient: R2_1 = -ln(1 - |s|/M) nats; joint adds linearly.
R_infty is INFINITE (support edges differ) -- stated, not hidden.
SUPERSEDED IN PART by the stronger conditional-uniformity result
(`accepted_response_uniform_chi2` in Rust, whitepaper Theorem 3):
accepted responses are EXACTLY uniform, so the unconditional bounds above
are valid but conservative. The former packing scalar v was removed after
variance analysis showed it encoded ||cw||2 (see whitepaper section 5).

Prints the table and asserts the pinned inequalities (exit nonzero if the
frozen constants ever violate them).
"""

import math
import sys

S = 65536
M = 2 * S + 1          # 131073
SHIFT = 16             # measured max |c*w| premise
N = 512                # 8 polys x 64 coeffs

tv1 = SHIFT / M
tvN = N * SHIFT / M
r2_1 = -math.log(1 - SHIFT / M)
r2N = N * r2_1

print(f"per-coeff TV  = {SHIFT}/{M} = {tv1:.6e} = 2^{math.log2(tv1):.2f}")
print(f"joint TV (union) = {N}*{SHIFT}/{M} = {tvN:.6f} (< 2^-4 = 0.0625: {tvN < 2**-4})")
print(f"per-coeff R2  = {r2_1:.6e} nats")
print(f"joint R2      = {r2N:.6f} nats (exp = {math.exp(r2N):.4f})")
print(f"R_inf         = INFINITE (support edges; documented, not claimed)")

ok = True
ok &= tv1 <= 2**-12
ok &= tvN < 2**-4
ok &= (16 * 512 * 16) <= M  # integer-exact form of joint TV <= 2^-4
print("PIN joint-TV-integer-exact:", (16 * 512 * 16) <= M)
print("RESULT " + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
