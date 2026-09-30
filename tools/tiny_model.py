#!/usr/bin/env python3
"""Tiny-model protocol mirror + running extractor (Q1 audit artifact).

Parameters: q'=17 (prime), d'=4, ring Z_17[X]/(X^4+1), 2x3 Ajtai matrix,
ternary witnesses, weight-2 challenges (24 total), masks in [-4, 4].

Transcript hash is hashlib.sha256 -- a MODEL substitution documented in
docs/extraction.md (the model tests protocol logic; the hash itself is
covered by BLAKE3 KATs + the byte-identical Build-B model).

Outputs one line: RESULT invert=A/B extracted=C/D grind=E/F
meaning:
  A/B  challenge pairs with invertible difference (rewind-usable),
  C/D  of those, pairs whose extracted witness satisfies A.w=y AND <w,w>=t
       (the packing closure, exhibited: must equal C/D with C == D),
  E/F  direct-grind accepts over F random (t1,z) trials. Expectation is
       NOT 1/24 (that is the forking error): each trial must satisfy
       n*d = 8 equations over Z_17, so per-trial accept is 17^-8 and the
       measured count must be 0.
"""

import hashlib
import itertools
import json
import sys

Q = 17
D = 4
NROWS, NCOLS = 2, 3
MASK_S = 4
RESP = 6  # S + max|c*w| = 4 + 2


def centered(v):
    v %= Q
    return v - Q if v > Q // 2 else v


def add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def sub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def negacyc_mul(a, b):
    acc = [0] * D
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            k = i + j
            if k < D:
                acc[k] = (acc[k] + x * y) % Q
            else:
                acc[k - D] = (acc[k - D] - x * y) % Q
    return acc


def inner(aa, bb):
    s = 0
    for pa, pb in zip(aa, bb):
        for x, y in zip(pa, pb):
            s += centered(x) * centered(y)
    return s % Q


def matvec(A, w):
    out = []
    for row in A:
        acc = [0] * D
        for a, p in zip(row, w):
            acc = add(acc, negacyc_mul(a, p))
        out.append(acc)
    return out


def all_challenges():
    out = []
    for pos in itertools.combinations(range(D), 2):
        for s0 in (1, Q - 1):
            for s1 in (1, Q - 1):
                c = [0] * D
                c[pos[0]] = s0
                c[pos[1]] = s1
                out.append(c)
    return out


CHALS = all_challenges()
assert len(CHALS) == 24, len(CHALS)

_INV_MEMO = {}


def invert_bruteforce(d):
    """Return d^{-1} mod (X^4+1, 17) by exhaustive search, or None (memoized)."""
    key = tuple(d)
    if key in _INV_MEMO:
        return _INV_MEMO[key]
    res = None
    for coeffs in itertools.product(range(Q), repeat=D):
        if negacyc_mul(d, list(coeffs)) == [1, 0, 0, 0]:
            res = list(coeffs)
            break
    _INV_MEMO[key] = res
    return res


def lcg(state):
    state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) % 2**64
    return state[0]


def rand_poly(state, bound):
    return [((lcg(state) % (2 * bound + 1)) - bound) % Q for _ in range(D)]


def tdigest(*parts):
    h = hashlib.sha256(b"tiny/v0.1|")
    for p in parts:
        h.update(repr(p).encode())
    return h.digest()


def main():
    state = [0x12345678]
    A = [[[lcg(state) % Q for _ in range(D)] for _ in range(NCOLS)] for _ in range(NROWS)]
    w = [[[0, 1, Q - 1][lcg(state) % 3] for _ in range(D)] for _ in range(NCOLS)]
    y = matvec(A, w)
    t = inner(w, w)

    r = [rand_poly(state, MASK_S) for _ in range(NCOLS)]
    t1 = matvec(A, r)
    u = inner(r, r)
    resps = {}
    for ci, c in enumerate(CHALS):
        cw = [negacyc_mul(c, p) for p in w]
        z = [add(rp, cp) for rp, cp in zip(r, cw)]
        assert all(abs(centered(x)) <= RESP for p in z for x in p), "tiny slack"
        resps[ci] = z

    inv = 0
    ext = 0
    total = 0
    for i, j in itertools.permutations(range(len(CHALS)), 2):
        total += 1
        d = sub(CHALS[i], CHALS[j])
        dinv = invert_bruteforce(d)
        if dinv is None:
            continue
        inv += 1
        dz = [sub(a, b) for a, b in zip(resps[i], resps[j])]
        wstar = [negacyc_mul(dinv, p) for p in dz]
        # ALL THREE claims checked on the recovered witness (exact):
        # linear, packing scalar, and shortness (ternary here).
        ok_lin = matvec(A, wstar) == y
        ok_pack = inner(wstar, wstar) == t
        ok_norm = all(abs(centered(x)) <= 1 for p in wstar for x in p)
        ok_euc = sum(centered(x) ** 2 for p in wstar for x in p) <= 64
        if ok_lin and ok_pack and ok_norm and ok_euc:
            ext += 1
        if total % 100 == 0:
            print(f"... extractor pair {total}/552", file=sys.stderr)

    trials = 2400
    acc = 0
    for _ in range(trials):
        rt1 = [[lcg(state) % Q for _ in range(D)] for _ in range(NROWS)]
        rz = [[lcg(state) % Q for _ in range(D)] for _ in range(NCOLS)]
        ci = int.from_bytes(tdigest(A, y, t, rt1, u)[:2], "little") % len(CHALS)
        c = CHALS[ci]
        good = True
        for rr in range(NROWS):
            lhs = [0] * D
            for arow, zp in zip(A[rr], rz):
                lhs = add(lhs, negacyc_mul(arow, zp))
            if lhs != add(rt1[rr], negacyc_mul(c, y[rr])):
                good = False
                break
        if good:
            acc += 1

    print(f"RESULT invert={inv}/{total} extracted={ext}/{inv} grind={acc}/{trials}")
    print(json.dumps({
        "pairs": total, "invertible": inv, "extracted": ext,
        "grind_trials": trials, "grind_accepts": acc,
        "q": Q, "d": D, "n_challenges": len(CHALS),
    }))


if __name__ == "__main__":
    main()
