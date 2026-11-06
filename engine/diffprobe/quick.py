#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
quick —— diffprobe 的一行式入口：从 URL 直接开测，不必手写 plan.json。

存在理由（2026-10-22 控制层复盘）：
  引擎本身没问题，慢在"写 plan JSON"这一步的摩擦。摩擦一高，就会退回
  "一条 curl 一个回合"的低密度串行扫描 —— 那才是把上下文烧光的真凶。
  本脚本只做两件事：把命令行参数翻译成 plan，然后**原样调用 diffprobe.py**。
  探测、比对、限速、破坏性闸门、落盘全部仍由 diffprobe 负责，不重复实现。

用法：
  python quick.py --url "https://t/path?a=1&b=2" --inject a --set sqli:boolean
  python quick.py --url "https://t/item/9/detail" --inject /item/{v}/detail --place path --set lfi:trav
  python quick.py --url "https://t/api/search" --place body --inject q --payloads "x,x',x AND 1=1"
  python quick.py ... --dry-run                 # 只渲染不发包
  python quick.py ... --mode paired             # 布尔/时间盲注 A-B 互比

等价旋钮（透传给 diffprobe）：--out --proxy --mode --timeout --insecure
                 --threads（默认 8）--delay-ms（默认 50）--sequential
节奏：默认 8 线程 / 50ms；命中 403/429/503 后自动降为单线程 <6/分钟。
固定内置：破坏性载荷默认拒发、未知端点不入批量。
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
ENGINE = HERE / "diffprobe.py"
QUICK_PLANS = HERE / "plans" / "_quick"


def slug(s: str) -> str:
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")
    return (s or "probe")[:60].lower()


def build_plan(a) -> dict:
    inject = {"place": a.place, "name": a.inject}
    if a.place == "path":
        inject = {"place": "path", "pattern": a.inject}
    method = a.method or ("POST" if a.place == "body" else "GET")
    plan = {
        "name": a.name or slug(a.url),
        "scheme": "https" if a.url.lower().startswith("https") else "http",
        "url": a.url,
        "method": method,
        "inject": [inject],
        "baseline_repeat": a.baseline_repeat,
        "time_band_ms": a.time_band,
        "stop_on_block": [403, 429, 503],
    }
    if a.rate and a.rate > 0:
        plan["rate_limit_per_min"] = a.rate
    if a.sequential:
        plan["threads"] = 1
    elif a.threads is not None:
        plan["threads"] = a.threads
    if a.delay_ms is not None:
        plan["delay_ms"] = a.delay_ms
    if a.markers:
        plan["markers"] = [m for m in a.markers.split("|") if m]
    if a.payloads:
        plan["payloads"] = [p for p in a.payloads.split(",") if p]
    else:
        plan["payload_sets"] = [s for s in a.set.split(",") if s]
    if a.baseline:
        plan["payloads"] = [p for p in plan.get("payloads", []) if p]
        plan.setdefault("payloads", []).insert(0, {"label": "baseline", "value": a.baseline, "baseline": True})
    if a.header:
        plan["headers"] = dict(h.split(":", 1) for h in a.header)
    return plan


def main(argv=None):
    ap = argparse.ArgumentParser(description="diffprobe 一行式入口（生成 plan 并调用引擎）")
    ap.add_argument("--url", required=True, help="目标 URL（含 host）")
    ap.add_argument("--inject", required=True, help="注入位名称；--place path 时是路径模式，如 /item/{v}/x")
    ap.add_argument("--place", default="query", choices=["query", "header", "cookie", "body", "path"])
    ap.add_argument("--method", help="HTTP 方法（默认 GET；--place body 时默认 POST）")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--set", help="载荷集引用，逗号分隔，如 sqli:boolean,xss:reflect")
    grp.add_argument("--payloads", help="字面载荷，逗号分隔")
    ap.add_argument("--baseline", help="基线值（字面载荷模式下强烈建议给，用于计算波动带）")
    ap.add_argument("--name", help="本次运行名（默认由 URL 推导）")
    ap.add_argument("--markers", help="WAF/报错特征关键字，竖线分隔")
    ap.add_argument("--header", action="append", help="附加请求头 K: V，可重复")
    ap.add_argument("--rate", type=int, default=0,
                    help="旧版串行限速（每分钟）；>0 时默认单线程按此速率，默认 0=用并发默认")
    ap.add_argument("--threads", type=int, default=None,
                    help="并发线程数（默认 8；1=单线程）")
    ap.add_argument("--delay-ms", type=int, default=None,
                    help="每个 worker 的请求间隔毫秒（默认 50）")
    ap.add_argument("--sequential", action="store_true", help="强制单线程")
    ap.add_argument("--block-delay-s", type=float, default=10.0,
                    help="触发防护后的串行间隔秒（默认 10 ⇒ <6/分钟）")
    ap.add_argument("--max-after-block", type=int, default=20,
                    help="触发防护后最多补发条数（默认 20）")
    ap.add_argument("--baseline-repeat", type=int, default=2)
    ap.add_argument("--time-band", type=int, default=800, help="耗时差分阈值 ms")
    ap.add_argument("--mode", default="single", choices=["single", "paired", "semantic", "matrix", "sequence"])
    ap.add_argument("--out", help="证据目录（默认 diffprobe/_runs/<name>）")
    ap.add_argument("--proxy", help="出站代理，如 http://127.0.0.1:7897")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    plan = build_plan(a)
    QUICK_PLANS.mkdir(parents=True, exist_ok=True)
    plan_path = QUICK_PLANS / (plan["name"] + ".json")
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")

    cmd = [sys.executable, str(ENGINE), "--plan", str(plan_path), "--timeout", str(a.timeout)]
    if a.out:
        cmd += ["--out", a.out]
    if a.proxy:
        cmd += ["--proxy", a.proxy]
    if a.mode != "single":
        cmd += ["--mode", a.mode]
    cmd += ["--block-delay-s", str(a.block_delay_s),
            "--max-after-block", str(a.max_after_block)]
    if a.sequential:
        cmd.append("--sequential")
    if a.insecure:
        cmd.append("--insecure")
    if a.dry_run:
        cmd.append("--dry-run")

    print("[quick] plan -> %s" % plan_path, file=sys.stderr)
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())