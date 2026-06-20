#!/usr/bin/env python3
"""Pull printable strings and flag crypto / SoC fingerprints.

The kernel usually tells you how the rootfs is protected. This greps a binary
for the words that give it away: hardware AES engines, SoC families, eFuse / OTP
key storage, the usual crypto libraries, and a few obfuscation tells.

Point it at the kernel image specifically. That is where the answer tends to be.

Companion to:
https://zero-entry.co.za/posts/firmware-xiongmai-vs-tplink-vigi/
"""
import argparse
import re

INDICATORS = [
    # hardware crypto / secure key storage
    "aesdma", "aes", "efuse", "otp", "secureboot", "secure boot", "trustzone",
    "rsa", "sha256", "hmac", "caam", "cryptodma", "keymaster",
    # SoC families common in cheap-to-mid gear
    "sstar", "infinity", "mstar", "sigmastar", "goke", "hisilicon", "hi35",
    "ingenic", "novatek", "fullhan", "grain media",
    # obfuscation / platform tells
    "xmfv", "xmeye", "obfusc", "xor",
]


def iter_strings(data, minlen=4):
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                yield start, cur.decode("ascii", "ignore")
            cur = bytearray()
    if len(cur) >= minlen:
        yield start, cur.decode("ascii", "ignore")


def main():
    ap = argparse.ArgumentParser(description="Flag crypto / SoC fingerprints in a binary.")
    ap.add_argument("file")
    ap.add_argument("-m", "--minlen", type=int, default=4)
    args = ap.parse_args()

    data = open(args.file, "rb").read()
    pat = re.compile("|".join(re.escape(w) for w in INDICATORS), re.I)

    seen = 0
    for off, s in iter_strings(data, args.minlen):
        if pat.search(s):
            seen += 1
            print(f"0x{off:08x}  {s.strip()}")

    print()
    if seen == 0:
        print("no obvious crypto / SoC strings.")
        print("try the kernel image specifically, or lower --minlen.")
    else:
        print(f"{seen} hit(s). cross-reference against the SoC datasheet to confirm the key path.")


if __name__ == "__main__":
    main()
