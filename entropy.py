#!/usr/bin/env python3
"""Sliding-window Shannon entropy over a file.

Used to tell encrypted / stream-cipher data (flat ~8.0 bits/byte, no structure)
apart from compressed data (high entropy too, but lumpy, with boundaries).

Companion to:
https://zero-entry.co.za/posts/firmware-xiongmai-vs-tplink-vigi/
"""
import argparse
import math
import sys
from collections import Counter


def entropy(block):
    if not block:
        return 0.0
    counts = Counter(block)
    n = len(block)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def main():
    ap = argparse.ArgumentParser(description="Sliding-window Shannon entropy.")
    ap.add_argument("file")
    ap.add_argument("-w", "--window", type=int, default=8192,
                    help="window size in bytes (default 8192; smaller windows under-read entropy)")
    ap.add_argument("-s", "--step", type=int, default=0,
                    help="step between windows (default: window size, non-overlapping)")
    ap.add_argument("--flat-threshold", type=float, default=7.9,
                    help="entropy at or above this counts as 'high' (default 7.9)")
    ap.add_argument("--csv", help="write per-window entropy to this CSV (for plotting)")
    args = ap.parse_args()

    if args.window <= 0:
        sys.exit("window must be a positive number of bytes")
    if args.step < 0:
        sys.exit("step cannot be negative")
    step = args.step or args.window
    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.exit(f"cannot read {args.file}: {e}")
    if not data:
        sys.exit("empty file")

    rows = []
    for off in range(0, max(1, len(data) - args.window + 1), step):
        rows.append((off, entropy(data[off:off + args.window])))
    if not rows:
        rows = [(0, entropy(data))]

    vals = [e for _, e in rows]
    mean = sum(vals) / len(vals)
    var = sum((v - mean) ** 2 for v in vals) / len(vals)
    above = sum(1 for v in vals if v >= args.flat_threshold) / len(vals) * 100

    print(f"file:        {args.file}")
    print(f"size:        {len(data)} bytes")
    print(f"windows:     {len(vals)} (window={args.window}, step={step})")
    print(f"entropy avg: {mean:.4f} bits/byte")
    print(f"entropy min: {min(vals):.4f}")
    print(f"entropy max: {max(vals):.4f}")
    print(f"variance:    {var:.6f}")
    print(f">= {args.flat_threshold}: {above:.2f}% of windows")
    print()

    if mean >= args.flat_threshold and var < 0.001:
        print("verdict: flat and high. Strong encryption, or data already compressed to near-random.")
        print("         confirm with xor_sweep.py (real crypto shows no magics) and binwalk")
        print("         (a compressed filesystem still has block boundaries; ciphertext does not).")
    elif mean >= 7.0:
        print("verdict: high but uneven. More like compression than encryption.")
        print("         look for block boundaries and headers with binwalk.")
    else:
        print("verdict: low to moderate. Plain or only lightly transformed data.")

    if args.csv:
        with open(args.csv, "w") as f:
            f.write("offset,entropy\n")
            for off, e in rows:
                f.write(f"{off},{e:.4f}\n")
        print(f"\nwrote {args.csv}")


if __name__ == "__main__":
    main()
