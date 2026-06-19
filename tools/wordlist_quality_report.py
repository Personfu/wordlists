#!/usr/bin/env python3
"""Generate a quality report for wordlists used in authorized labs.

This helps remove junk, duplicates, and unsafe personal-data artifacts before
wordlists are used in CTFs, classroom ranges, or contracted assessments.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

RISK_MARKERS = ("ssn", "dob", "passworddump", "leaked", "combo", "credential")


def main() -> None:
    parser = argparse.ArgumentParser(description="Report quality metrics for wordlist files.")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()

    for path in args.paths:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace").splitlines()
        nonempty = [line.strip() for line in text if line.strip()]
        unique = set(nonempty)
        risky = [line for line in nonempty if any(marker in line.lower() for marker in RISK_MARKERS)]
        print(f"file: {path}")
        print(f"  bytes: {len(raw)}")
        print(f"  sha256: {hashlib.sha256(raw).hexdigest()}")
        print(f"  lines: {len(text)}")
        print(f"  nonempty: {len(nonempty)}")
        print(f"  unique: {len(unique)}")
        print(f"  duplicate_ratio: {0 if not nonempty else 1 - (len(unique) / len(nonempty)):.3f}")
        print(f"  risky_marker_lines: {len(risky)}")
        if risky:
            print("  warning: review possible personal-data/credential artifacts before use")


if __name__ == "__main__":
    main()
