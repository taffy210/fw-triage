#!/usr/bin/env python3
"""Single-byte XOR sweep.

Cheap gear loves to hide behind a one-byte XOR and call it encryption. Before
you declare AES, rule that out: XOR the blob against all 256 keys and look for
known file magics, or for the output turning into mostly-printable text
(readable strings are a strong tell you hit the right key).

Note: entropy is *not* a useful signal here. Single-byte XOR is a bijection on
the byte alphabet, so it leaves the byte-frequency distribution — and therefore
the Shannon entropy — unchanged for every key. We score printable-ASCII ratio
instead, which actually varies with the key.

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


def printable_ratio(block):
    """Fraction of bytes that are printable ASCII (plus tab/newline/CR). Unlike
    entropy, this changes with the XOR key, so it's a usable signal for spotting
    the key that turns a blob back into config/text."""
    if not block:
        return 0.0
    printable = sum(1 for b in block if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(block)


def main():
    ap = argparse.ArgumentParser(description="Single-byte XOR sweep for file magics / printable text.")
    ap.add_argument("file")
    ap.add_argument("-n", "--bytes", type=int, default=65536,
                    help="how much of the file to test (default 64K)")
    args = ap.parse_args()

    try:
        with open(args.file, "rb") as f:
            data = f.read(args.bytes)
    except OSError as e:
        sys.exit(f"cannot read {args.file}: {e}")
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
        # tar's "ustar" magic sits at offset 257, not 0, so check it explicitly.
        if x[257:262] == b"ustar":
            found.append("tar")
        if found:
            hits += 1
            print(f"key 0x{k:02x}: {', '.join(found)}")

    print()
    if hits == 0:
        # Entropy can't rank keys (it's XOR-invariant), so fall back to the
        # padding heuristic: firmware is full of 0x00 runs, and 0x00 ^ key == key,
        # so the most common byte is the single most likely key. Report it (with
        # how printable the result looks) as a lead rather than flagging noise.
        guess = Counter(data).most_common(1)[0][0]
        pr = printable_ratio(bytes(b ^ guess for b in data[:4096]))
        print("no known file magic under any single-byte key.")
        print(f"best key guess (most common byte, = 0x00 padding under XOR): "
              f"0x{guess:02x} -> {pr * 100:.0f}% printable at the start")
        print(f"try:  xor 0x{guess:02x} and re-run binwalk; if entropy was flat "
              f"~8.0 with no structure, suspect real crypto (AES etc.).")
    else:
        print(f"{hits} candidate key(s) above. Single-byte XOR is plausible, go verify the full file.")


if __name__ == "__main__":
    main()
