#!/usr/bin/env python3
"""Core-SVP cost estimates for the 0l0 SIS instance (Q4 audit artifact).

Self-validating: parses D/Q/N_ROWS/M_COLS from src/params.rs and refuses to
run if they differ from the hardcoded analysis inputs (no param drift).

Model (standard, same as public estimators at the formula level):
  SIS lattice dim d = m*D, det = q^(n*D) (random Ajtai matrix, w.h.p.).
  Gaussian heuristic gh = sqrt(d/(2*pi*e)) * det^(1/d).
  BKZ-beta achieves root-Hermite delta(beta) ~= (beta/(2*pi*e))^(1/(2*(beta-1)))
  (Chen-Nguyen), giving shortest vector ~= delta^d * det^(1/d).
  For target norm B: needed delta = (B / det^(1/d))^(1/d); invert for beta
  by binary search; costs 2^(0.292*beta) classical / 2^(0.265*beta) quantum.
Targets: response-level kernel (2*RESP*sqrt(512)), mask recovery, witness.
"""

import math
import re
import sys

SRC = open("src/params.rs").read()


def const_int(name):
    m = re.search(rf"pub const {name}:\s*\w+\s*=\s*([\d_]+);", SRC)
    assert m, f"const {name} not found"
    return int(m.group(1).replace("_", ""))


D = const_int("D")
Q = const_int("Q")
NROWS = const_int("N_ROWS")
MCOLS = const_int("M_COLS")
RESP = const_int("RESP_BOUND")
BETA = const_int("BETA")

# Analysis inputs (must match frozen params or the script aborts).
assert (D, Q, NROWS, MCOLS) == (64, 1073750017, 4, 8), "param drift!"
assert RESP == 65472 and BETA == 1

d = MCOLS * D            # 512
logdet = NROWS * D * math.log(Q)   # ln det
gh = math.sqrt(d / (2 * math.pi * math.e)) * math.exp(logdet / d)


def delta_of_beta(beta):
    return (beta / (2 * math.pi * math.e)) ** (1.0 / (2 * (beta - 1)))


def beta_for_norm(B):
    # need delta^d * det^(1/d) <= B  ->  delta <= (B / det^(1/d))^(1/d)
    need = (B / math.exp(logdet / d)) ** (1.0 / d)
    if need <= delta_of_beta(d):
        return d  # at-or-below estimator floor: full-dimension regime
    lo, hi = 50, d
    while delta_of_beta(hi) > need:
        hi = min(d, hi + 50)
        if hi >= d:
            break
    while lo < hi:
        mid = (lo + hi) // 2
        if delta_of_beta(mid) <= need:
            hi = mid
        else:
            lo = mid + 1
    return lo


def report(name, B):
    beta = beta_for_norm(B)
    floored: bool = beta >= 512
    tag: str = " (>=512 floor)" if floored else ""
    cl = 0.292 * beta
    qu = 0.265 * beta
    print(f"{name:28s} B={B:>10.0f}  beta={beta:>4d}{tag}  classical 2^{cl:.1f}  quantum 2^{qu:.1f}")
    return beta


print(f"SIS lattice: dim={d} log2(det)={logdet / math.log(2):.1f} GH={gh:.0f}")
print("Targets are attacker goals; costs are Core-SVP BKZ estimates.")
print("(>=512 floor) = at/below estimator resolution, not an exact figure.")
b1 = report("response-level kernel", 2 * 65472 * math.sqrt(512))
b2 = report("mask recovery", 65536 * math.sqrt(512))
b3 = report("ternary witness", math.sqrt(512))


def bkz_tour_simulate(beta, tours=30):
    """Simplified BKZ simulator (Chen-Nguyen structure, teaching-grade).

    Profile r[i] = ln||b*_i|| starts geometric at LLL slope
    (delta_LLL ~= 1.02) normalized to the determinant. Each tour sweeps
    blocks [j, j+beta): the block's first vector is pulled down to the
    block Gaussian heuristic, preserving block volume by spreading the
    difference over the rest. Returns shortest length found (exp(r[0])).
    Simplified: no insertion reordering, no auto-abort, fixed tours --
    validates the ORDER of the closed-form numbers, not exact constants.
    """
    slope0 = 2.0 * math.log(1.02)
    # geometric profile with mean logdet/d
    r = [(logdet / d) + slope0 * ((d - 1) / 2.0 - i) for i in range(d)]
    for _ in range(tours):
        for j in range(d):
            k = min(j + beta, d)
            m = k - j
            if m < 2:
                continue
            vol = sum(r[j:k])
            gh = vol / m + 0.5 * math.log(m / (2 * math.pi * math.e))
            if r[j] > gh:
                diff = r[j] - gh
                r[j] = gh
                for t in range(j + 1, k):
                    r[t] += diff / (m - 1)
    return math.exp(r[0])


print("BKZ tour simulation (30 tours, simplified model):")
for beta in (104, 145, 200):
    got = bkz_tour_simulate(beta)
    closed = (delta_of_beta(beta) ** d) * math.exp(logdet / d)
    print(f"  beta={beta:>4d}  simulated shortest={got:.0f}  closed-form={closed:.0f}  "
          f"ratio={got / closed:.2f}")

print("RESULT " + ("MARGINAL (see docs/lattice-margin.md)" if min(b1, b2) < 300 else "OK"))
sys.exit(0)
