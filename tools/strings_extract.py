#!/usr/bin/env python3
"""
strings_extract.py — Extract ASCII / UTF-16LE strings from a binary (Sysinternals strings style).

Part of ZETA CYBERLAB toolkit: https://github.com/fanximing111/Reverse-Engineering-Assistant-Prompt

Usage:
    python strings_extract.py <file> [-n MIN_LEN] [--enc ascii|utf16le|all] [--head N]

Pure stdlib. Output: offset (hex)  string
"""
import argparse
import re
import sys


def main():
    ap = argparse.ArgumentParser(description="Extract strings from binary files")
    ap.add_argument("file")
    ap.add_argument("-n", "--min-len", type=int, default=4, help="min length (default 4)")
    ap.add_argument("--enc", choices=["ascii", "utf16le", "all"], default="all")
    ap.add_argument("--head", type=int, default=0, help="only print first N matches")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()

    hits = []
    if args.enc in ("ascii", "all"):
        for m in re.finditer(rb"[\x20-\x7E]{%d,}" % args.min_len, data):
            hits.append((m.start(), m.group().decode("latin-1")))
    if args.enc in ("utf16le", "all"):
        for m in re.finditer(rb"(?:[\x20-\x7E]\x00){%d,}" % args.min_len, data):
            s = m.group().decode("utf-16-le")
            # skip if it is just the ascii-decoded shadow of the same range
            hits.append((m.start(), s))

    hits.sort(key=lambda h: h[0])
    shown = 0
    for off, s in hits:
        print(f"0x{off:08X}  {s}")
        shown += 1
        if args.head and shown >= args.head:
            break
    if not hits:
        print("no strings found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
