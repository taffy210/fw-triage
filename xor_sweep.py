#!/usr/bin/env python3
"""Single-byte XOR sweep.

Cheap gear loves to hide behind a one-byte XOR and call it encryption. Before
you declare AES, rule that out: XOR the blob against all 256 keys and look for
known file magics or a collapse in entropy.

Companion to:
https://zero-entry.co.za/posts/firmware-xiongmai-vs-tplink-vigi/
"""
import argparse
import math
import sys
from collections import Counter

MAGICS = {
    b"\x1f\x8b": "gzip",
    b"\xfd7zXZ\x00": "xz",
    b"BZh": "bzip2",
    b"hsqs": "squashfs (LE)",
    b"sqsh": "squashfs (BE)",
    b"\x85\x19": "jffs2",
    b"\x7fELF": "ELF",
    b"\x27\x05\x19\x56": "u-boot uImage",
    b"ustar": "tar",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x04\x22\x4d\x18": "lz4",
    b"ANDROID!": "android boot",
}


def entropy(block):
    if not block:
        return 0.0
    c = Counter(block)
    n = len(block)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    ap = argparse.ArgumentParser(description="Single-byte XOR sweep for magics / entropy drop.")
    ap.add_argument("file")
    ap.add_argument("-n", "--bytes", type=int, default=65536,
                    help="how much of the file to test (default 64K)")
    ap.add_argument("--entropy-drop", type=float, default=7.0,
                    help="flag keys whose output entropy falls below this (default 7.0)")
    args = ap.parse_args()

    data = open(args.file, "rb").read(args.bytes)
    if not data:
        sys.exit("empty file")

    base = entropy(data)
    print(f"baseline entropy (first {len(data)} bytes): {base:.4f}")
    print()

    hits = 0
    for k in range(256):
        x = bytes(b ^ k for b in data)
        # Check the very start only. A single-byte XOR of a whole image or section
        # puts the format magic at offset 0. Scanning the whole buffer for short
        # magics just manufactures false positives on high-entropy data.
        found = [name for magic, name in MAGICS.items() if x.startswith(magic)]
        if found:
            hits += 1
            print(f"key 0x{k:02x}: {', '.join(found)}")
        elif base >= 7.5 and entropy(x[:4096]) < args.entropy_drop:
            hits += 1
            print(f"key 0x{k:02x}: entropy drops to {entropy(x[:4096]):.3f}, worth a look")

    print()
    if hits == 0:
        print("no single-byte XOR hits. Not XOR.")
        print("if entropy was flat ~8.0, suspect real crypto (AES etc.) and go read the kernel strings.")
    else:
        print(f"{hits} candidate key(s) above. Single-byte XOR is plausible, go verify the full file.")


if __name__ == "__main__":
    main()
