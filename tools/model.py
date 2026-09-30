#!/usr/bin/env python3
"""Independent full-protocol model of 0l0 (Q5 audit artifact).

Reimplements from the spec (docs/spec.md): BLAKE3 compression + tree hash,
XOF cascade, ring arithmetic (naive AND NTT, cross-checked), matrix
expansion, transcript, commit, prove, verify. Produces BYTE-IDENTICAL proofs
to the Rust implementation for the same inputs -- see tools/diff_vectors.py.

No third-party packages (stdlib only). Blake3 here is written from the
algorithm spec and verified against the official KATs at import test time
(run tools/diff_vectors.py --kat-only for the fast check).
"""

import struct
import sys

# ---------------------------------------------------------------- parameters
D = 64
Q = 1073750017
NROWS, MCOLS = 4, 8
BETA, B_NORM = 1, 64
MASK_S, RESP = 65536, 65472
CHAL_W = 16
TAU = 2
RETRIES = 8
PROOF_BYTES = 1 + TAU * (1024 + 1088) + 288 + 64
assert PROOF_BYTES == 4577, PROOF_BYTES
PROOF_VERSION = 2

IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
SCHED = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
]
M32 = 0xFFFFFFFF


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def g(st, a, b, c, d, mx, my):
    st[a] = (st[a] + st[b] + mx) & M32
    st[d] = rotr(st[d] ^ st[a], 16)
    st[c] = (st[c] + st[d]) & M32
    st[b] = rotr(st[b] ^ st[c], 12)
    st[a] = (st[a] + st[b] + my) & M32
    st[d] = rotr(st[d] ^ st[a], 8)
    st[c] = (st[c] + st[d]) & M32
    st[b] = rotr(st[b] ^ st[c], 7)


def compress(cv, block, counter, blen, flags):
    m = list(struct.unpack("<16I", bytes(block)))
    st = list(cv) + IV[:4] + [counter & M32, (counter >> 32) & M32, blen, flags]
    for r in range(7):
        s = SCHED[r]
        g(st, 0, 4, 8, 12, m[s[0]], m[s[1]])
        g(st, 1, 5, 9, 13, m[s[2]], m[s[3]])
        g(st, 2, 6, 10, 14, m[s[4]], m[s[5]])
        g(st, 3, 7, 11, 15, m[s[6]], m[s[7]])
        g(st, 0, 5, 10, 15, m[s[8]], m[s[9]])
        g(st, 1, 6, 11, 12, m[s[10]], m[s[11]])
        g(st, 2, 7, 8, 13, m[s[12]], m[s[13]])
        g(st, 3, 4, 9, 14, m[s[14]], m[s[15]])
    return st


def cv_words(block, cv, counter, blen, flags):
    st = compress(cv, block, counter, blen, flags)
    return [(st[i] ^ st[i + 8]) & M32 for i in range(8)]


def cv_bytes(block, cv, counter, blen, flags):
    return b"".join(struct.pack("<I", w) for w in cv_words(block, cv, counter, blen, flags))


def blake3(data: bytes) -> bytes:
    assert len(data) <= 32 * 1024
    if len(data) <= 1024:
        return _single_chunk(data)
    n = (len(data) + 1023) // 1024
    cvs = [_chunk_cv(data[i * 1024:(i + 1) * 1024], i) for i in range(n)]
    while len(cvs) > 1:
        nxt = []
        i = 0
        while i < len(cvs):
            if i + 1 < len(cvs):
                root = (len(cvs) == 2 and len(nxt) == 0)
                nxt.append(_parent(cvs[i], cvs[i + 1], root))
                i += 2
            else:
                nxt.append(cvs[i])
                i += 1
        cvs = nxt
    return cvs[0]


def _chunk_cv(chunk: bytes, ctr: int) -> bytes:
    cv = list(IV)
    nb = (len(chunk) + 63) // 64
    for i in range(nb):
        blk = chunk[i * 64:(i + 1) * 64]
        fl = 0
        if i == 0:
            fl |= 1
        if i == nb - 1:
            fl |= 2
        blk = blk + b"\x00" * (64 - len(blk))
        cv = cv_words(blk, cv, ctr, len(chunk[i * 64:(i + 1) * 64]), fl)
    return struct.pack("<8I", *cv)


def _single_chunk(chunk: bytes) -> bytes:
    if not chunk:
        return cv_bytes(bytes(64), IV, 0, 0, 1 | 2 | 8)
    cv = list(IV)
    nb = (len(chunk) + 63) // 64
    for i in range(nb):
        part = chunk[i * 64:(i + 1) * 64]
        blk = part + b"\x00" * (64 - len(part))
        fl = 0
        if i == 0:
            fl |= 1
        if i == nb - 1:
            fl |= 2 | 8
        cv = cv_words(blk, cv, 0, len(part), fl)
    return struct.pack("<8I", *cv)


def _parent(l: bytes, r: bytes, root: bool) -> bytes:
    fl = 4 | (8 if root else 0)
    return cv_bytes(l + r, IV, 0, 64, fl)


def xof(data: bytes, tag: int, n: int) -> bytes:
    assert n <= 2048
    out = b""
    if len(data) <= 256:
        ctr = 0
        while len(out) < n:
            out += blake3(data + bytes([tag]) + struct.pack("<Q", ctr))
            ctr += 1
    else:
        pre = blake3(blake3(data) + bytes([tag]))
        ctr = 0
        while len(out) < n:
            out += blake3(pre + bytes([tag]) + struct.pack("<Q", ctr))
            ctr += 1
    return out[:n]


# ---------------------------------------------------------------- ring
def centered(v):
    v %= Q
    return v - Q if v > Q // 2 else v


def padd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def pmul_naive(a, b):
    acc = [0] * D
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            k = i + j
            if k < D:
                acc[k] = (acc[k] + x * y) % Q
            else:
                acc[k - D] = (acc[k - D] - x * y) % Q
    return acc


W64 = 817737403
PSI = 187094501
NINV = pow(64, Q - 2, Q)
PSI_POW = [1]
for _ in range(D - 1):
    PSI_POW.append(PSI_POW[-1] * PSI % Q)


def _bitrev(x):
    r = 0
    for _ in range(6):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


def _ntt(a, root):
    t = [a[_bitrev(i)] for i in range(D)]
    ln = 1
    while ln < D:
        wl = pow(root, D // (2 * ln), Q)
        i = 0
        while i < D:
            w = 1
            for j in range(ln):
                u = t[i + j]
                v = t[i + j + ln] * w % Q
                t[i + j] = (u + v) % Q
                t[i + j + ln] = (u - v) % Q
                w = w * wl % Q
            i += 2 * ln
        ln *= 2
    return t


def pmul_nwc(a, b):
    ap = [x * p % Q for x, p in zip(a, PSI_POW)]
    bp = [x * p % Q for x, p in zip(b, PSI_POW)]
    cp = _ntt(ap, W64)
    dp = _ntt(bp, W64)
    ep = [x * y % Q for x, y in zip(cp, dp)]
    fp = [(x * NINV) % Q for x in _ntt(ep, pow(W64, 63, Q))]
    pinv, cur = [1], 1
    psi_inv = pow(PSI, 127, Q)
    for _ in range(D - 1):
        cur = cur * psi_inv % Q
        pinv.append(cur)
    return [(x * p) % Q for x, p in zip(fp, pinv)]


def inner(aa, bb):
    return sum(centered(x) * centered(y) for pa, pb in zip(aa, bb)
               for x, y in zip(pa, pb)) % Q


def matvec(A, w):
    out = []
    for row in A:
        acc = [0] * D
        for a, p in zip(row, w):
            acc = padd(acc, pmul_nwc(a, p))
        out.append(acc)
    return out


# ---------------------------------------------------------------- transcript
class T:
    def __init__(self, domain: bytes):
        self.s = blake3(domain)

    def absorb(self, label: bytes, data: bytes):
        assert len(label) <= 64 and len(data) <= 2048
        if len(data) <= 1024:
            self.s = blake3(self.s + label + struct.pack("<H", len(data)) + data)
        else:
            self.s = blake3(self.s + label + struct.pack("<H", len(data)) + blake3(data))

    def chal(self, tag: int) -> bytes:
        return xof(self.s, tag, 32)


# ---------------------------------------------------------------- protocol
def expand_matrix(seed: bytes):
    A = []
    for r in range(NROWS):
        row = []
        for c in range(MCOLS):
            vals = None
            for attempt in range(8):
                stream = xof(seed + bytes([0x41, r, c, attempt]), 0x41, 2048)
                # NOTE: mirrors Rust retry loop byte-for-byte (same domains).
                vals, pos = [], 0
                while len(vals) < D and pos + 4 <= len(stream):
                    v = struct.unpack("<I", stream[pos:pos + 4])[0]
                    pos += 4
                    if v < Q:
                        vals.append(v)
                if len(vals) >= D:
                    break
            if vals is None or len(vals) < D:
                raise RuntimeError("matrix shortfall")
            row.append(vals[:D])
        A.append(row)
    return A


def sample_witness(A, seed: bytes):
    stream = xof(seed, 0x77, 1024)
    w, pos = [], 0
    for _ in range(MCOLS):
        p = []
        for _ in range(D):
            p.append([0, 1, Q - 1][stream[pos] % 3])
            pos += 1
        w.append(p)
    return w, matvec(A, w), inner(w, w)


def sample_mask(seed: bytes):
    R = 2 * MASK_S + 1
    bound = (2**32 // R) * R
    out = []
    for c in range(MCOLS):
        stream = xof(seed + bytes([0x6D, c]), 0x42, 512)
        vals, pos = [], 0
        while len(vals) < D:
            v = struct.unpack("<I", stream[pos:pos + 4])[0]
            pos += 4
            if v < bound:
                vals.append((v % R) - MASK_S)
            if pos + 4 > len(stream):
                raise RuntimeError("mask shortfall")
        out.append([v % Q for v in vals])
    return out


def expand_chal(seed: bytes):
    stream = xof(seed, 0x50, 128)
    used, out, placed = [False] * D, [0] * D, 0
    for b in stream[:96]:
        if placed >= CHAL_W:
            break
        p = b % D
        if not used[p]:
            used[p] = True
            out[p] = 1 if (stream[96 + placed] & 1) == 0 else Q - 1
            placed += 1
    p = 0
    while placed < CHAL_W and p < D:
        if not used[p]:
            used[p] = True
            out[p] = 1
            placed += 1
        p += 1
    return out


def prove(A, w, y, t, salt: bytes) -> bytes:
    assert len(salt) == 32
    body = bytearray(PROOF_BYTES - 1)
    uvs = []
    for j in range(TAU):
        for attempt in range(RETRIES):
            seed = blake3(salt + bytes([j, attempt]))
            r = sample_mask(seed)
            t1 = matvec(A, r)
            u = inner(r, r)
            tr = T(b"sq-pq/v0.1/R*")
            pbytes = D.to_bytes(8, "little") + Q.to_bytes(4, "little") \
                + BETA.to_bytes(4, "little") + B_NORM.to_bytes(4, "little") \
                + RESP.to_bytes(4, "little") + bytes([TAU, PROOF_VERSION]) + b"\x00" * 6
            tr.absorb(b"params", pbytes)
            tr.absorb(b"A", blake3(flat_mat(A)))
            tr.absorb(b"y", flat_polys(y))
            tr.absorb(b"t", struct.pack("<I", t))
            tr.absorb(b"salt", salt)
            tr.absorb(b"round", bytes([j]))
            tr.absorb(b"t1", flat_polys(t1))
            tr.absorb(b"u", struct.pack("<I", u))
            c = expand_chal(tr.chal(0x50))
            cw = [pmul_nwc(c, p) for p in w]
            z = [padd(rp, cp) for rp, cp in zip(r, cw)]
            # Packing scalar REMOVED (audit finding): its variance encodes
            # ||cw||2 (w = 0 forces v == 0), a witness distinguisher through
            # the only non-response wire value. Slots stay zero (as in Rust).
            v = 0
            if all(abs(centered(x)) <= RESP for p in z for x in p):
                break
        else:
            raise RuntimeError("sampling exhausted")
        off = j * 2112
        body[off:off + 1024] = flat_polys(t1)
        body[off + 1024:off + 2112] = pack_z(z)
        uvs += [u, v]
    for i, v in enumerate(uvs):
        body[4224 + i * 4:4224 + (i + 1) * 4] = struct.pack("<I", v)
    body[4512:4544] = salt
    return bytes([PROOF_VERSION]) + bytes(body)


def flat_polys(polys):
    b = b""
    for p in polys:
        for c in p:
            b += struct.pack("<I", c)
    return b


def pack_z(z):
    # 17-bit LSB-first offset-binary, coeff-major; mirrors encode_z_packed.
    out = bytearray(1088)
    acc = bits = pos = 0
    for p in z:
        for c in p:
            v = c if c <= 65472 else c - Q
            assert -65472 <= v <= 65472, "model encodes valid z only"
            e = v + 65536
            acc |= e << bits
            bits += 17
            while bits >= 8:
                out[pos] = acc & 0xFF
                acc >>= 8
                bits -= 8
                pos += 1
    assert pos == 1088 and bits == 0
    return bytes(out)


def unpack_z(raw):
    assert len(raw) == 1088
    out, acc, bits, pos = [], 0, 0, 0
    cur = []
    for _ in range(8 * 64):
        while bits < 17:
            acc |= raw[pos] << bits
            bits += 8
            pos += 1
        w = acc & 0x1FFFF
        acc >>= 17
        bits -= 17
        assert 64 <= w <= 131008, f"non-canonical word {w}"
        v = w - 65536
        cur.append(v % Q)
        if len(cur) == 64:
            out.append(cur)
            cur = []
    return out


def verify(A, y, t, proof: bytes) -> bool:
    if len(proof) != PROOF_BYTES or proof[0] != PROOF_VERSION:
        return False
    body = proof[1:]
    if any(body[4240:4512]) or any(body[4544:]):
        return False
    # Pack v slots canonically zero (F24 malleability fix, mirrors Rust).
    if any(body[4228:4232]) or any(body[4236:4240]):
        return False
    salt = body[4512:4544]
    for i in range(4):
        if struct.unpack("<I", body[4224 + i * 4:4228 + i * 4])[0] >= Q:
            return False
    for j in range(TAU):
        base = j * 2112
        t1 = [list(struct.unpack("<64I", body[base + r * 256:base + (r + 1) * 256]))
              for r in range(NROWS)]
        if any(c >= Q for p in t1 for c in p):
            return False
        zb = base + 1024
        z = unpack_z(bytes(body[zb:zb + 1088]))
        u = struct.unpack("<I", body[4224 + 2 * j * 4:4228 + 2 * j * 4])[0]
        tr = T(b"sq-pq/v0.1/R*")
        pbytes = D.to_bytes(8, "little") + Q.to_bytes(4, "little") \
            + BETA.to_bytes(4, "little") + B_NORM.to_bytes(4, "little") \
            + RESP.to_bytes(4, "little") + bytes([TAU, PROOF_VERSION]) + b"\x00" * 6
        tr.absorb(b"params", pbytes)
        tr.absorb(b"A", blake3(flat_mat(A)))
        tr.absorb(b"y", flat_polys(y))
        tr.absorb(b"t", struct.pack("<I", t))
        tr.absorb(b"salt", salt)
        tr.absorb(b"round", bytes([j]))
        tr.absorb(b"t1", flat_polys(t1))
        tr.absorb(b"u", struct.pack("<I", u))
        c = expand_chal(tr.chal(0x50))
        for r in range(NROWS):
            lhs = [0] * D
            for arow, zp in zip(A[r], z):
                lhs = padd(lhs, pmul_nwc(arow, zp))
            rhs = padd(t1[r], pmul_nwc(c, y[r]))
            if lhs != rhs:
                return False
        if any(abs(centered(x)) > RESP for p in z for x in p):
            return False
    return True


def flat_mat(A):
    b = b""
    for row in A:
        for p in row:
            for c in p:
                b += struct.pack("<I", c)
    return b
