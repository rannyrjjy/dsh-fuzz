#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fuzz_verify.py - post-action state read for diffprobe plans.

For every payload in a finished diffprobe run, render the plan's verify request
and read the configured JSON paths. The mutation itself is not replayed: this
runner verifies the state after the batch, so use it with a single injected
value or a read-only object check. It never sends a request without --allow-write
when the verify template is a write method.

Usage:
  python engine/fuzz/fuzz_verify.py --plan <plan.json> --run <run-dir> [--dry-run] [--allow-write]
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def render(template: str, payload: str) -> str:
    return template.replace("{{PE}}", urllib.parse.quote(payload, safe="")).replace("{{P}}", payload)


def parse_raw(text: str) -> dict:
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    method, path = lines[0].split()[:2]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    return {"method": method.upper(), "path": path, "headers": headers, "body": body}


def host_of(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "host":
            return v
    raise ValueError("verify template is missing Host header")


def json_path(obj, path: str):
    cur = obj
    for part in path.split("."):
        if not part:
            continue
        m = re.match(r"^([^\[]*)(?:\[(\d+)\])?$", part)
        if not m:
            return None
        key, idx = m.group(1), m.group(2)
        if key:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return None
        if idx is not None:
            if isinstance(cur, list) and int(idx) < len(cur):
                cur = cur[int(idx)]
            else:
                return None
    return cur


def send(raw: str, scheme: str, timeout: int = 20) -> tuple[int, str, str]:
    req = parse_raw(raw)
    url = f"{scheme}://{host_of(req['headers'])}{req['path']}"
    headers = {k: v for k, v in req["headers"].items() if k.lower() not in ("host", "content-length")}
    data = req["body"].encode("utf-8") if req["body"] else None
    request = urllib.request.Request(url, data=data, headers=headers, method=req["method"])
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(request, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, "\n".join(f"{k}: {v}" for k, v in resp.headers.items()), body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return exc.code, str(exc.headers), body


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser()
    p.add_argument("--plan", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--allow-write", action="store_true")
    args = p.parse_args()

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8-sig"))
    verify = plan.get("verify") or {}
    template = verify.get("request") or verify.get("request_template")
    paths = list(verify.get("paths") or [])
    if not template or not paths:
        print(json.dumps({"ok": True, "skipped": True, "reason": "no verify request or paths"},
                         ensure_ascii=False))
        return 0
    scheme = plan.get("scheme") or "https"
    req0 = parse_raw(render(template, "1"))
    if req0["method"] not in ("GET", "HEAD", "OPTIONS") and not args.allow_write:
        print(json.dumps({"ok": False, "error": "verify method is a write; pass --allow-write"},
                         ensure_ascii=False))
        return 2

    run_dir = Path(args.run)
    diffs = run_dir / "diffs.csv"
    if not diffs.exists():
        print(json.dumps({"ok": False, "error": f"missing {diffs}"}, ensure_ascii=False))
        return 2
    rows = []
    with io.open(diffs, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for r in csv.DictReader(fh):
            rows.append(r)
    if not rows:
        print(json.dumps({"ok": False, "error": "empty diffs.csv"}, ensure_ascii=False))
        return 2

    rate = int(plan.get("rate_limit_per_min") or 12)
    gap = 60.0 / max(1, rate)
    out_rows = []
    baseline_vals: dict[str, object] = {}
    first_row = rows[0]
    vdir = run_dir / "verify"
    vdir.mkdir(parents=True, exist_ok=True)
    last = 0.0
    for row in rows[:10]:
        label = row.get("label") or "row"
        payload = row.get("payload") or ""
        raw = render(template, payload)
        if args.dry_run:
            out_rows.append({"label": label, "path": "-", "baseline": "", "value": "(dry-run)",
                             "changed": "false", "evidence": raw.split("\n", 1)[0]})
            continue
        now = time.time()
        if now - last < gap:
            time.sleep(gap - (now - last))
        try:
            status, headers, body = send(raw, scheme)
            last = time.time()
        except Exception as exc:
            out_rows.append({"label": label, "path": "-", "baseline": "", "value": "",
                             "changed": "false", "evidence": f"error: {exc}"})
            continue
        safe = re.sub(r"[^\w\-.]", "_", label)[:40]
        ev = vdir / f"{safe}.resp"
        ev.write_text(f"HTTP {status}\n{headers}\n\n{body}", encoding="utf-8")
        try:
            obj = json.loads(body)
        except Exception:
            obj = None
        for path in paths:
            val = json_path(obj, path) if obj is not None else None
            if label == "baseline" or (row is first_row and path not in baseline_vals):
                baseline_vals[path] = val
            base = baseline_vals.get(path)
            changed = base is not None and val is not None and str(base) != str(val)
            out_rows.append({"label": label, "path": path, "baseline": "" if base is None else str(base),
                             "value": "" if val is None else str(val),
                             "changed": "true" if changed else "false",
                             "evidence": ev.name})

    state = run_dir / "state.csv"
    with io.open(state, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["label", "path", "baseline", "value", "changed", "evidence"])
        w.writeheader()
        w.writerows(out_rows)
    changed = sum(1 for r in out_rows if r["changed"] == "true")
    print(json.dumps({"ok": True, "state": str(state), "rows": len(out_rows),
                      "changed": changed, "dryRun": bool(args.dry_run)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
