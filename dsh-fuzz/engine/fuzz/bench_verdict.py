#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bench_verdict.py - offline regression for fuzz_ops.classify_row.

Scans every 漏洞记录/**/diffs.csv produced by diffprobe and compares the
classifier against the engine's own verdict label. No network, no writes.

Usage:
  python engine/fuzz/bench_verdict.py [--evidence <dir>] [--verbose]
Exit 0 when every labelled row is classified consistently (or when the evidence
directory is absent, which simply means there is nothing to regress yet).
"""
from __future__ import annotations

import argparse
import collections
import csv
import io
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzz_ops  # noqa: E402

ROOT = Path(os.environ.get("DSH_FUZZ_WORKSPACE") or Path.cwd()).resolve()
REC = Path(os.environ.get("DSH_FUZZ_EVIDENCE") or ROOT / "漏洞记录")


def expected(row: dict) -> str:
    verdict = (row.get("verdict") or "").strip()
    semantic = (row.get("semantic") or "").strip().upper()
    if "无效" in verdict:
        return "INVALID"
    if "命中防护" in verdict:
        return "BLOCKED"
    if "无差分" in verdict:
        return "NO_SIGNAL"
    if "差分" in verdict or semantic == "DIFF":
        return "DIFFERENTIAL"
    if "基线" in verdict or not verdict:
        return "BASELINE"
    return "OTHER:" + verdict[:20]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", help="evidence root containing */diffs.csv (default: $DSH_FUZZ_EVIDENCE or <workspace>/漏洞记录)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    rec = Path(args.evidence).resolve() if args.evidence else REC
    if not rec.is_dir():
        print(f"skip: no evidence directory at {rec} (nothing to regress)")
        return 0
    files = 0
    rows = 0
    labels = collections.Counter()
    mismatches = []
    for p in rec.rglob("diffs.csv"):
        files += 1
        try:
            with io.open(p, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                for row in csv.DictReader(fh):
                    rows += 1
                    exp = expected(row)
                    labels[exp] += 1
                    if exp in ("BASELINE",) or exp.startswith("OTHER:"):
                        continue
                    got = fuzz_ops.classify_row(row)
                    if got != exp:
                        mismatches.append((str(p.relative_to(rec.parent)), row.get("label", ""), exp, got))
        except Exception:
            continue
    print(f"files={files} rows={rows} labels={dict(labels)}")
    print(f"mismatches={len(mismatches)}")
    for m in mismatches[:20]:
        print("  ", m)
    if mismatch := mismatches:
        return 1
    print("OK: classifier matches every labelled row")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
