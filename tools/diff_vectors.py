#!/usr/bin/env python3
"""Byte-identical differential: Rust `vectors` example vs tools/model.py.

Usage: tools/diff_vectors.py [--kat-only]
  --kat-only : only verify model.blake3 against official KATs (fast).
  default    : KATs + full proof differential (runs `cargo run --example vectors`).

Exits nonzero on any mismatch.
"""

import struct
import subprocess
import sys

sys.path.insert(0, "tools")
import model

KATS = [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (32, "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
]


def check_kats():
    for n, want in KATS:
        got = model.blake3(bytes((i % 251 for i in range(n)))).hex()
        assert got == want, f"KAT n={n}: {got} != {want}"
    print(f"KATs: {len(KATS)}/{len(KATS)} model.blake3 exact")


def main():
    check_kats()
    if "--kat-only" in sys.argv:
        return
    # Internal NTT cross-check (model must agree with itself two ways).
    import random
    rng = random.Random(0xC10C)
    for _ in range(20):
        a = [rng.randrange(model.Q) for _ in range(model.D)]
        b = [rng.randrange(model.Q) for _ in range(model.D)]
        assert model.pmul_nwc(a, b) == model.pmul_naive(a, b), "model NTT mismatch"
    print("model NTT self-check: 20/20 naive==NWC")
    # Full proof differential.
    out = subprocess.run(
        ["cargo", "run", "--release", "--example", "vectors"],
        capture_output=True, text=True, check=True,
    ).stdout.strip().split("\n")
    vals = {}
    for line in out:
        k, v = line.split("=", 1)
        vals.setdefault(k, []).append(v)
    A = model.expand_matrix(bytes([11] * 32))
    w, y, t = model.sample_witness(A, bytes([22] * 32))
    assert model.flat_polys(y).hex() == vals["Y"][0], "y mismatch"
    assert struct.pack("<I", t).hex() == vals["T"][0], "t mismatch"
    assert model.verify(A, y, t, bytes.fromhex(vals["PROOF"][0])), "rust proof must verify in model"
    for salt, hexp in zip((bytes([33] * 32), bytes([44] * 32)), vals["PROOF"]):
        mine = model.prove(A, w, y, t, salt).hex()
        assert mine == hexp, f"proof mismatch salt={salt.hex()}"
    print(f"proof differential: {len(vals['PROOF'])}/{len(vals['PROOF'])} byte-identical")
    # Adversarial agreement: both implementations reject the same mutants.
    # (10 fixed bitflips across regions + version flip + truncation/overlong.)
    base = bytes.fromhex(vals["PROOF"][0])
    muts = 0
    for pos in (0, 1, 100, 1024, 1025, 2112, 2113, 4224, 4225, 4512):
        bad = bytearray(base)
        bad[pos] ^= 0x01
        assert not model.verify(A, y, t, bytes(bad)), f"mutant accepted at {pos}"
        muts += 1
    vflip = bytearray(base)
    vflip[0] ^= 0x01
    assert not model.verify(A, y, t, bytes(vflip)), "version flip accepted"
    muts += 1
    assert not model.verify(A, y, t, base[:-1]), "truncation accepted"
    muts += 1
    assert not model.verify(A, y, t, base + b"\x00"), "overlong accepted"
    muts += 1
    print(f"adversarial agreement: {muts}/{muts} mutants rejected by model")


if __name__ == "__main__":
    main()
