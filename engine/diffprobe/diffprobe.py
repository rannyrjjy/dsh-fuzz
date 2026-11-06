#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
差分探针 harness —— 把 payload 矩阵的"发包 + 比对"从模型上下文搬进脚本。

痛点（历史复盘）：
  · hqcwc 单个注入点 40+ 条变体，每条一次请求 + 一轮推理
  · njtech 2000+ 个散落探针输出文件，无索引、不可比对
解答：一次跑完整矩阵 → 每条交换落盘 raw 请求/响应 → **只把差分行喂回模型**。

用法：
  python diffprobe.py --plan plans/example-vsb-dynclicks.json
  python diffprobe.py --plan plans/example-vsb-dynclicks.json --dry-run
  python diffprobe.py --plan plans/example-vsb-dynclicks.json --out evidence/run1

纪律（内置，不可绕过除非显式 --allow-destructive）：
  · 默认 8 线程、每请求 50ms；命中封禁信号后自动降为单线程 <6/分钟
  · 计时敏感载荷（SLEEP/WAITFOR/...）自动退回单线程，避免并发污染时间差
  · 破坏性载荷（DROP/DELETE/UPDATE/INSERT/TRUNCATE/SHUTDOWN/xp_cmdshell/INTO OUTFILE）
    一律拒发
  · 命中 stop_on_block（默认 403/429/503）进入降级模式并如实记录
"""

import argparse
import csv
import difflib
import hashlib
import io
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = Path(__file__).resolve().parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import dp_semantic as dps  # noqa: E402

# 出站代理（由 --proxy 或 plan 的 proxy 字段设置）。为空则直连。
# 适用于本机直连被沙箱/环境变量封死、必须经用户代理出口的场景。
PROXY = None

DEFAULT_DENY = [
    r"drop\s+table", r"delete\s+from", r"update\s+\w+\s+set", r"insert\s+into",
    r"truncate\s+table", r"\bshutdown\b", r"xp_cmdshell", r"sp_configure",
    r"into\s+outfile", r"into\s+dumpfile", r"\bexec\s+master", r"\bkill\s+\d+",
    r"\bmkdir\b", r"\brm\s+-rf\b", r"\bformat\s+c:",
]

# 动作型破坏端点：只匹配请求行/路径，避免误伤 /format/json 这类响应格式后缀。
ACTION_DENY = [
    r"/formate",                                  # formateappslog 等
    r"/format_apps", r"/formatpartition", r"/formatdisk",
    r"/(?:rebuild|repair|factory|wipe|restore|destroy)(?=/|$|\s|\?)",
    r"/(?:delete|remove|reset|shutdown|reboot)(?=/|$|\s|\?)",
    r"[?&](?:action|op|do|cmd|method)=(?:delete|remove|reset|rebuild|repair|format|wipe|restore|shutdown|reboot)\b",
]
ALLOW_DESTRUCTIVE = False

DEFAULT_STOP_STATUS = [403, 429, 503]

PAYLOADSETS_DIR = HERE.parent / "payloadsets"


def _load_set_lib(name):
    r"""按名字加载 .\payloadsets\<name>.json（该目录是共享弹药库）。"""
    fname = name if name.endswith(".json") else name + ".json"
    p = PAYLOADSETS_DIR / fname
    if not p.exists():
        avail = ", ".join(sorted(x.stem for x in PAYLOADSETS_DIR.glob("*.json"))) or "(空)"
        raise SystemExit("[error] 找不到弹药库 %s，可用：%s" % (fname, avail))
    with io.open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


def resolve_payload_sets(plan):
    r"""把 payload_sets / markers_from 展开成字面 payloads 与 markers。

    payload_sets: ["sqli:boolean", "sqli:error"]   ——  引用 .\payloadsets\sqli.json 的集合
    markers_from: ["sqli_error", "waf_block"]      ——  引用 signals.json 的标记预设
    """
    payloads = list(plan.get("payloads") or [])
    for ref in (plan.pop("payload_sets", None) or []):
        lib_name, _, set_name = ref.partition(":")
        lib = _load_set_lib(lib_name)
        sets = lib.get("sets") or {}
        picked = [set_name] if set_name else sorted(sets)
        for sn in picked:
            if sn not in sets:
                raise SystemExit("[error] 弹药库 %s 无集合 %r，可用：%s" % (lib_name, sn, ", ".join(sorted(sets))))
            for i, v in enumerate(sets[sn], 1):
                payloads.append({"label": "%s-%s-%02d" % (lib_name, sn, i), "value": v})

    markers = list(plan.get("markers") or [])
    for ref in (plan.pop("markers_from", None) or []):
        lib_name, sep, set_name = ref.partition(":")
        if not sep:
            lib_name, set_name = "signals", ref
        lib = _load_set_lib(lib_name)
        presets = lib.get("presets") or {}
        if set_name not in presets:
            raise SystemExit("[error] %s 无标记预设 %r，可用：%s" % (lib_name, set_name, ", ".join(sorted(presets))))
        markers.extend(presets[set_name])

    plan["payloads"] = payloads
    plan["markers"] = markers
    return plan


def load_plan(path, mode="single"):
    with io.open(path, "r", encoding="utf-8-sig") as fh:
        plan = json.load(fh)
    plan.setdefault("scheme", "https")
    plan["_rate_explicit"] = "rate_limit_per_min" in plan
    plan.setdefault("rate_limit_per_min", 20)
    plan.setdefault("baseline_repeat", 3)
    plan.setdefault("time_band_ms", 800)
    plan.setdefault("markers", [])
    plan.setdefault("deny_patterns", DEFAULT_DENY)
    plan.setdefault("stop_on_block", DEFAULT_STOP_STATUS)
    plan.setdefault("name", Path(path).stem)
    if "request_template" not in plan and plan.get("inject"):
        plan["request_template"] = synthesize_template(plan)
    if "request_template" not in plan and mode in ("single", "paired", "matrix"):
        raise SystemExit("[error] plan 缺 request_template（或 url + inject）")
    resolve_payload_sets(plan)
    if mode == "single" and not plan.get("payloads"):
        raise SystemExit("[error] plan 缺 payloads（或 payload_sets 展开为空）")
    if mode == "paired" and not plan.get("pairs"):
        raise SystemExit("[error] paired 模式需要 plan.pairs（[[A, B], ...]）")
    if mode == "matrix" and not (plan.get("identities") and plan.get("objects")):
        raise SystemExit("[error] matrix 模式需要 plan.identities 与 plan.objects")
    if mode == "sequence" and not plan.get("sequence"):
        raise SystemExit("[error] sequence 模式需要 plan.sequence")
    return plan


def synthesize_template(plan):
    """参数位模式：给 url + inject，自动拼出 raw HTTP 模板（用于没有 Burp 原文时）。

    inject: {"place": "query|header|cookie|body|path", "name": "id", ...}
      - query/body 用 {{PE}}（URL 编码后嵌入），header/cookie 用 {{P}}（原样嵌入）
      - path 需要 "pattern"（如 "/item/{v}/detail"）
      - 只支持单注入点；多注入点请拆成多个 plan
    """
    inject = plan["inject"]
    if len(inject) > 1:
        raise SystemExit("[error] inject 只支持 1 个注入点，多注入点请拆成多个 plan")
    pt = inject[0]
    if isinstance(pt, str):
        pt = {"place": "query", "name": pt}
    place = pt.get("place", "query")
    name = pt.get("name")
    url = plan.get("url") or plan.get("target")
    if not url:
        raise SystemExit("[error] inject 模式需要 plan.url")
    method = (plan.get("method") or "GET").upper()
    headers = dict(plan.get("headers") or {})
    body = plan.get("body")
    sp = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
    path = sp.path or "/"

    if place == "query":
        if not name:
            raise SystemExit("[error] inject.place=query 需要 name")
        if name in [k for k, _ in query]:
            query = [(k, "{{PE}}" if k == name else v) for k, v in query]
        else:
            query.append((name, "{{PE}}"))
    elif place == "path":
        pattern = pt.get("pattern")
        if not pattern:
            raise SystemExit("[error] inject.place=path 需要 pattern，如 /item/{v}/detail")
        path = path.replace(pattern, pattern.replace("{v}", "{{PE}}"))
    elif place == "header":
        if not name:
            raise SystemExit("[error] inject.place=header 需要 name")
        headers[name] = "{{P}}"
    elif place == "cookie":
        if not name:
            raise SystemExit("[error] inject.place=cookie 需要 name")
        ck = headers.get("Cookie", "")
        if name in ck:
            ck = re.sub(r"(%s=)[^;]*" % re.escape(name), lambda m: m.group(1) + "{{P}}", ck)
        else:
            ck = (ck + "; " if ck else "") + "%s={{P}}" % name
        headers["Cookie"] = ck
    elif place == "body":
        if not name:
            raise SystemExit("[error] inject.place=body 需要 name")
        if (pt.get("content_type") or "form") == "json":
            data = json.loads(body) if body else {}
            data[name] = "{{P}}"
            body = json.dumps(data, ensure_ascii=False)
            headers.setdefault("Content-Type", "application/json")
        elif body and name in body:
            body = re.sub(r"(%s=)[^&]*" % re.escape(name), lambda m: m.group(1) + "{{PE}}", body)
        else:
            body = (body + "&" if body else "") + "%s={{PE}}" % name
    else:
        raise SystemExit("[error] inject.place 只能是 query/header/cookie/body/path")

    qs = "&".join("%s=%s" % (k, v) for k, v in query)   # 不 urlencode，保住 {{PE}} 占位符
    target = path + (("?" + qs) if qs else "")
    lines = ["%s %s HTTP/1.1" % (method, target), "Host: %s" % sp.netloc]
    if not any(k.lower() == "host" for k in headers):
        pass
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    lines.append("")
    if body and method not in ("GET", "HEAD"):
        lines.append(body)
    return "\n".join(lines)


def render_raw(template, payload):
    """{{P}} 原样嵌入，{{PE}} URL 编码后嵌入。"""
    out = template.replace("{{PE}}", urllib.parse.quote(payload, safe=""))
    out = out.replace("{{P}}", payload)
    return out


def parse_raw(raw):
    """返回 dict(method, path, version, headers(list[(k,v)]), body)"""
    text = raw.replace("\r\n", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    lines = [ln for ln in head.split("\n")]
    if not lines or not lines[0].strip():
        raise ValueError("空请求行")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("请求行不合法: %s" % lines[0])
    method, path = parts[0], parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return {"method": method, "path": path, "version": version,
            "headers": headers, "body": body}


def build_url(req, scheme):
    host = None
    for k, v in req["headers"]:
        if k.lower() == "host":
            host = v
            break
    if not host:
        raise ValueError("模板缺 Host 头")
    path = req["path"]
    if not path.startswith("/"):
        path = "/" + path
    return "%s://%s%s" % (scheme, host, path)


def check_destructive(raw, patterns):
    low = raw.lower()
    hits = [p for p in patterns if re.search(p, low)]
    if not ALLOW_DESTRUCTIVE:
        reqline = low.split("\n", 1)[0]
        hits += [p for p in ACTION_DENY if re.search(p, reqline)]
    return hits


class RateLimiter:
    def __init__(self, per_min):
        self.gap = 60.0 / max(1, per_min)
        self.last = 0.0
        self.count = 0

    def wait(self):
        now = time.time()
        delta = now - self.last
        if delta < self.gap:
            time.sleep(self.gap - delta)
        self.last = time.time()
        self.count += 1


class Pacer:
    r"""并发节奏器：默认 N 线程、每请求 delay 秒；命中封禁后串行 <6/分钟。

    未封禁：每个 worker 发送前 sleep(delay)，N 个 worker 并行推进。
    封禁后：全局串行锁 + block_delay_s（默认 10s ⇒ <6/分钟），最多补发
    max_after_block 条；超过后剩余任务记「未发送（防护中断）」。
    """

    def __init__(self, threads=8, delay_ms=50, block_delay_s=10.0, max_after_block=20):
        self.threads = max(1, int(threads))
        self.delay = max(0.0, float(delay_ms) / 1000.0)
        self.block_delay = max(0.0, float(block_delay_s))
        self.max_after_block = max(0, int(max_after_block))
        self._blocked = threading.Event()
        self._stop = threading.Event()
        self._seq_lock = threading.Lock()
        self._post_block = 0
        self.lock = threading.Lock()  # 供调用方做计数等短临界区

    @property
    def blocked(self):
        return self._blocked.is_set()

    @property
    def stopped(self):
        return self._stop.is_set()

    def block(self):
        self._blocked.set()

    def stop(self):
        self._stop.set()

    def wait(self):
        """返回 False 表示不要再发（已停止）。"""
        if self._stop.is_set():
            return False
        if not self._blocked.is_set():
            if self.delay:
                time.sleep(self.delay)
            return True
        with self._seq_lock:
            if self._stop.is_set():
                return False
            if self._post_block >= self.max_after_block:
                self._stop.set()
                return False
            if self.block_delay:
                time.sleep(self.block_delay)
            self._post_block += 1
            return True

    def snapshot(self):
        return {"threads": self.threads, "delay_ms": int(round(self.delay * 1000)),
                "blocked": self.blocked, "post_block": self._post_block,
                "stopped": self.stopped}


TIMING_RE = re.compile(
    r"(?i)(?:\bsleep\s*\(|\bwaitfor\s+delay\b|\bpg_sleep\s*\(|"
    r"\bbenchmark\s*\(|dbms_pipe\.receive_message|\bdelay\s*['\"]?\s*\d)")


def _is_timing_sensitive(plan, mode):
    """计时盲注/延时类载荷不能并发，否则并发抖动会污染 Δms。"""
    if plan.get("timing_sensitive"):
        return True
    vals = []
    if mode == "paired":
        for pair in plan.get("pairs") or []:
            vals.extend(pair if isinstance(pair, (list, tuple)) else [pair])
    elif mode == "single":
        for it in plan.get("payloads") or []:
            vals.append(it if isinstance(it, str) else it.get("value", ""))
    return any(TIMING_RE.search(str(v)) for v in vals)


def _ssl_ctx(insecure, legacy=False):
    """insecure=不校验证书；legacy=放开 SECLEVEL 与最低版本，兼容只跑老旧 TLS 的 IoT/网络设备。"""
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    if legacy:
        for setter in (
            lambda: setattr(ctx, "minimum_version", ssl.TLSVersion.TLSv1),
            lambda: ctx.set_ciphers("DEFAULT@SECLEVEL=0:ALL:aNULL"),
            lambda: setattr(ctx, "options", ctx.options | getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)),
            lambda: setattr(ctx, "verify_flags", getattr(ssl, "VERIFY_X509_TRUSTED_FIRST", 0)),
        ):
            try:
                setter()
            except Exception:
                pass
    return ctx


def _opener(insecure, legacy_tls):
    """构造 opener：可选代理 + 可控 TLS 上下文。
    urlopen(context=...) 会绕开已安装的代理 opener，故这里显式 build_opener。"""
    ctx = _ssl_ctx(insecure, legacy_tls) if (insecure or legacy_tls) else ssl.create_default_context()
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if PROXY:
        handlers.append(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    return urllib.request.build_opener(*handlers)


def send(req, url, timeout=20, insecure=True, legacy_tls=False):
    headers = dict((k, v) for k, v in req["headers"] if k.lower() != "host")
    data = req["body"].encode("utf-8") if req["body"] else None
    if data is not None and not any(k.lower() == "content-length" for k, _ in req["headers"]):
        headers["Content-Length"] = str(len(data))
    r = urllib.request.Request(url, data=data, headers=headers, method=req["method"].upper())
    op = _opener(insecure, legacy_tls)
    t0 = time.time()
    try:
        with op.open(r, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
            hdrs = resp.headers
    except urllib.error.HTTPError as e:
        body = e.read()
        status = e.code
        hdrs = e.headers
    except Exception as e:  # 连接层失败也如实记录
        elapsed = int((time.time() - t0) * 1000)
        return {"status": 0, "headers": [], "body": b"", "ms": elapsed,
                "error": "%s: %s" % (type(e).__name__, e)}
    elapsed = int((time.time() - t0) * 1000)
    return {"status": status,
            "headers": list(hdrs.items()) if hdrs else [],
            "body": body, "ms": elapsed, "error": ""}


def dump_exchange(path_req, path_resp, raw_req, url, res):
    with io.open(path_req, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(raw_req.rstrip("\n") + "\n")
        fh.write("\n# -> %s\n" % url)
    body_text = res["body"].decode("utf-8", errors="replace")
    with io.open(path_resp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("HTTP/1.1 %s\n" % res["status"])
        for k, v in res["headers"]:
            fh.write("%s: %s\n" % (k, v))
        if res.get("error"):
            fh.write("\n# ERROR %s\n" % res["error"])
        fh.write("\n")
        fh.write(body_text)


def digest(b):
    return hashlib.sha256(b).hexdigest()[:16]


def markers_hit(body_text, markers):
    return [m for m in markers if m and m in body_text]


def median(vals):
    if not vals:
        return 0
    s = sorted(vals)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def run(plan, outdir, dry_run=False, insecure=True, timeout=20, pacer=None):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pacer = pacer or Pacer()
    records = [None] * len(plan["payloads"])
    tasks = []
    idx = 0

    for pos, item in enumerate(plan["payloads"]):
        if isinstance(item, str):
            item = {"label": item, "value": item}
        label = str(item.get("label") or ("p%d" % pos))
        value = item.get("value", "")
        raw = render_raw(plan["request_template"], value)
        safe_label = re.sub(r"[^0-9A-Za-z\-_.]", "_", label)[:40]
        idx += 1

        # 注意：{{PE}} 会把载荷 URL 编码，必须把原始载荷一并纳入检查，
        # 否则 `DROP TABLE` 编码成 %20 后能绕过拒发（自检时实测到的真实绕过）。
        decoded = urllib.parse.unquote(raw)
        hits = check_destructive(raw + "\n" + decoded + "\n" + value, plan["deny_patterns"])
        if hits:
            records[pos] = {
                "label": label, "payload": value, "status": "-", "len": 0,
                "ms": 0, "delta_ms": 0, "sha256": "-", "markers": "",
                "verdict": "拒发", "reason": "破坏性载荷：%s" % ",".join(hits[:3]),
                "evidence": "-",
            }
            continue

        try:
            req = parse_raw(raw)
            url = build_url(req, plan["scheme"])
        except Exception as exc:
            records[pos] = {
                "label": label, "payload": value, "status": "-", "len": 0,
                "ms": 0, "delta_ms": 0, "sha256": "-", "markers": "",
                "verdict": "模板错误", "reason": str(exc), "evidence": "-",
            }
            continue

        if dry_run:
            records[pos] = {
                "label": label, "payload": value, "status": "(dry)", "len": 0,
                "ms": 0, "delta_ms": 0, "sha256": "-", "markers": "",
                "verdict": "未发送", "reason": url, "evidence": "-",
            }
            continue

        tasks.append((pos, idx, label, value, raw, req, url, safe_label, item))

    def work(t):
        pos, tidx, label, value, raw, req, url, safe_label, item = t
        if not pacer.wait():
            return pos, {
                "label": label, "payload": value, "status": "-", "len": 0,
                "ms": 0, "delta_ms": 0, "sha256": "-", "markers": "",
                "verdict": "未发送（防护中断）", "reason": "封禁后达到补发上限",
                "evidence": "-",
            }
        res = send(req, url, timeout=timeout, insecure=insecure,
                   legacy_tls=bool(plan.get("tls_legacy")))
        body_text = res["body"].decode("utf-8", errors="replace")
        rq = outdir / ("%03d_%s.req" % (tidx, safe_label))
        rs = outdir / ("%03d_%s.resp" % (tidx, safe_label))
        dump_exchange(rq, rs, raw, url, res)
        rec = {
            "label": label, "payload": value, "status": res["status"],
            "len": len(res["body"]), "ms": res["ms"], "delta_ms": 0,
            "sha256": digest(res["body"]),
            "markers": ",".join(markers_hit(body_text, plan["markers"])),
            "verdict": "待判", "reason": res.get("error", ""),
            "evidence": str(rs),
            "is_baseline": bool(item.get("is_baseline")),
            "body": res["body"],
            "headers": res.get("headers") or [],
        }
        if res["status"] in plan["stop_on_block"]:
            pacer.block()
        return pos, rec

    if tasks:
        with ThreadPoolExecutor(max_workers=pacer.threads) as ex:
            futs = {ex.submit(work, t): t for t in tasks}
            for fut in as_completed(futs):
                t = futs[fut]
                try:
                    pos, rec = fut.result()
                except Exception as exc:
                    pos, rec = t[0], {
                        "label": t[2], "payload": t[3], "status": "-", "len": 0,
                        "ms": 0, "delta_ms": 0, "sha256": "-", "markers": "",
                        "verdict": "错误", "reason": "%s: %s" % (type(exc).__name__, exc),
                        "evidence": "-"}
                records[pos] = rec

    for i, rec in enumerate(records):
        if rec is None:
            records[i] = {"label": "p%d" % i, "payload": "", "status": "-", "len": 0,
                          "ms": 0, "delta_ms": 0, "sha256": "-", "markers": "",
                          "verdict": "未发送（防护中断）", "reason": "未派发",
                          "evidence": "-"}

    blocked = next((r["status"] for r in records
                    if r.get("status") in plan["stop_on_block"]), None)
    stopped = next((r["label"] for r in records
                    if r.get("status") in plan["stop_on_block"]), None)
    result = _analyze(plan, records, blocked, stopped)
    result["concurrency"] = pacer.snapshot()
    return result


def _sim(a, b):
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000]).ratio()


PAIR_COLS = ["pair", "label_a", "label_b", "status_a", "status_b", "len_a", "len_b",
             "net_len", "ms_a", "ms_b", "delta_ms", "similarity", "markers",
             "verdict", "reason", "evidence_a", "evidence_b"]


def run_pairs(plan, outdir, dry_run=False, insecure=True, timeout=20, pacer=None):
    """A/B 配对模式：不依赖基线，两发互比。适合布尔盲注、时间盲注、ID 相邻对照。

    净长度差 net_len = (len_b − len_a) − (len(B) − len(A))，抵消载荷自身长度差与回显干扰。
    并发粒度是“对”：同一对的 A/B 串行发送（保住时间差语义），不同对并行。
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pacer = pacer or Pacer()
    pairs = plan.get("pairs") or []
    for pj, pair in enumerate(pairs, 1):
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise SystemExit("[error] pairs 每项必须是 [A, B] 两元素，出错项：%r" % (pair,))
    rows = [None] * len(pairs)
    tol = float(plan.get("pair_len_tol", 0))
    sent = [0]
    sent_lock = threading.Lock()

    def work(pj, pair):
        obs = []
        for side_i, side in enumerate(("A", "B")):
            value = pair[side_i]
            raw = render_raw(plan["request_template"], value)
            decoded = urllib.parse.unquote(raw)
            hits = check_destructive(raw + "\n" + decoded + "\n" + value, plan["deny_patterns"])
            if hits:
                obs.append({"value": value, "error": "拒发 破坏性载荷：%s" % ",".join(hits[:3])})
                continue
            try:
                req = parse_raw(raw)
                url = build_url(req, plan["scheme"])
            except Exception as exc:
                obs.append({"value": value, "error": "模板错误：%s" % exc})
                continue
            if dry_run:
                obs.append({"value": value, "dry": True, "url": url, "raw": raw})
                continue
            if not pacer.wait():
                obs.append({"value": value, "error": "未发送（防护中断）"})
                continue
            res = send(req, url, timeout=timeout, insecure=insecure,
                       legacy_tls=bool(plan.get("tls_legacy")))
            with sent_lock:
                sent[0] += 1
            tidx = (pj - 1) * 2 + side_i + 1
            safe = re.sub(r"[^\w\-.]", "_", "pair%d%s" % (pj, side))[:40]
            rq = outdir / ("%03d_%s.req" % (tidx, safe))
            rs = outdir / ("%03d_%s.resp" % (tidx, safe))
            dump_exchange(rq, rs, raw, url, res)
            obs.append({"value": value, "status": res["status"], "body": res["body"],
                        "ms": res["ms"], "raw": raw, "url": url,
                        "evidence": "%s / %s" % (rq.name, rs.name)})
            if res["status"] in plan["stop_on_block"]:
                pacer.block()

        a, b = obs[0], obs[1]
        row = {"pair": pj, "label_a": repr(pair[0]), "label_b": repr(pair[1]),
               "status_a": a.get("status", "(dry)"), "status_b": b.get("status", "(dry)"),
               "len_a": len(a.get("body") or b""), "len_b": len(b.get("body") or b""),
               "net_len": 0, "ms_a": a.get("ms", 0), "ms_b": b.get("ms", 0),
               "delta_ms": 0, "similarity": "-", "markers": "",
               "verdict": "未发送", "reason": "", "evidence_a": a.get("evidence", "-"),
               "evidence_b": b.get("evidence", "-")}

        if a.get("error") or b.get("error"):
            row["verdict"] = "拒发/错误"
            row["reason"] = a.get("error") or b.get("error")
            return pj - 1, row
        if a.get("dry") or b.get("dry"):
            row["reason"] = "%s vs %s" % (a.get("url"), b.get("url"))
            return pj - 1, row

        net = (row["len_b"] - row["len_a"]) - (len(pair[1]) - len(pair[0]))
        row["net_len"] = net
        row["delta_ms"] = row["ms_b"] - row["ms_a"]
        ta = a["body"].decode("utf-8", "replace")
        tb = b["body"].decode("utf-8", "replace")
        sim = _sim(ta, tb)
        row["similarity"] = "%.4f" % sim
        row["markers"] = ",".join(m for m in plan["markers"] if m and m in tb and m not in ta)

        reasons = []
        if row["status_a"] != row["status_b"]:
            reasons.append("状态码 %s→%s" % (row["status_a"], row["status_b"]))
        if abs(net) > tol:
            reasons.append("净长度差 %+d" % net)
        if abs(row["delta_ms"]) >= plan["time_band_ms"]:
            reasons.append("耗时差 %+dms 超带宽 %dms" % (row["delta_ms"], plan["time_band_ms"]))
        if row["markers"]:
            reasons.append("命中标记 %s" % row["markers"])
        if sim < 0.995 and not reasons:
            reasons.append("响应体相似度 %.4f" % sim)
        row["verdict"] = "DIFF" if reasons else "SAME"
        row["reason"] = "；".join(reasons) or "两发在四个维度上一致"
        return pj - 1, row

    if pairs:
        with ThreadPoolExecutor(max_workers=pacer.threads) as ex:
            futs = {ex.submit(work, pj, pair): (pj - 1, pair)
                    for pj, pair in enumerate(pairs, 1)}
            for fut in as_completed(futs):
                i, pair = futs[fut]
                try:
                    _, row = fut.result()
                except Exception as exc:
                    row = {"pair": i + 1, "label_a": repr(pair[0]), "label_b": repr(pair[1]),
                           "status_a": "-", "status_b": "-", "len_a": 0, "len_b": 0,
                           "net_len": 0, "ms_a": 0, "ms_b": 0, "delta_ms": 0,
                           "similarity": "-", "markers": "", "verdict": "错误",
                           "reason": "%s: %s" % (type(exc).__name__, exc),
                           "evidence_a": "-", "evidence_b": "-"}
                rows[i] = row

    blocked = None
    stopped = None
    for r in rows:
        if not r:
            continue
        hit_a = r.get("status_a") in plan["stop_on_block"]
        hit_b = r.get("status_b") in plan["stop_on_block"]
        if hit_a or hit_b:
            blocked = r.get("status_a") if hit_a else r.get("status_b")
            stopped = "pair%d" % r["pair"]
            break

    return {"name": plan["name"], "pairs": rows, "blocked": blocked,
            "stopped": stopped, "requests": sent[0], "concurrency": pacer.snapshot()}


def report_pairs(result):
    lines = ["", "=== 配对判定：%s ===" % result["name"], ""]
    conc = result.get("concurrency") or {}
    if conc:
        lines.append("节奏：%s 线程 / %sms%s" % (
            conc.get("threads"), conc.get("delay_ms"),
            "；已触发防护，后续单线程 <6/分钟" if conc.get("blocked") else ""))
    diffs = [r for r in result["pairs"] if r["verdict"] == "DIFF"]
    lines.append("配对 %d 组 ｜ 有差分 %d 组 ｜ 请求 %d 次" % (
        len(result["pairs"]), len(diffs), result["requests"]))
    for r in result["pairs"]:
        lines.append("  [%-8s] %s vs %s → %s" % (r["verdict"], r["label_a"], r["label_b"], r["reason"]))
        if r["evidence_a"] != "-":
            lines.append("             证据 %s / %s" % (r["evidence_a"], r["evidence_b"]))
    if result["blocked"]:
        conc = result.get("concurrency") or {}
        tail = ("已进入单线程 <6/分钟降级，达到补发上限后停止"
                if conc.get("blocked") else "已进入降级模式")
        lines.append("")
        lines.append("!! 触发防护（%s，%s）——%s；该目标标记「已触发防护」" % (
            result["blocked"], result["stopped"], tail))
    lines.append("")
    lines.append("判定纪律：DIFF 只代表两发存在差异，须扩大样本后才能定性；SAME 是该假设的证伪依据。")
    return "\n".join(lines)


def _hdr_block(headers):
    return "\n".join("%s: %s" % (k, v) for k, v in (headers or {}).items())


def run_matrix(plan, outdir, dry_run=False, insecure=True, timeout=20, pacer=None):
    r"""多身份 × 多对象 权限矩阵。

    为什么不能只做 A/B：越权的最小证据是"**同一对象、不同主体**"的差异，
    对照组必须包含"自己的对象"（应允许）与"他人的对象"（应拒绝），
    否则无法排除"该接口本来就公开"。
    并发粒度是“格”：不同身份×对象组合并行；结果按行列汇总。
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pacer = pacer or Pacer()
    identities = plan.get("identities") or []
    objects = plan.get("objects") or []
    if not identities or not objects:
        raise SystemExit("[error] matrix 模式需要 plan.identities 与 plan.objects")
    rows = [str(i.get("label") or i.get("name")) for i in identities]
    cols = [str(o.get("label") or o.get("value")) for o in objects]
    cells, tasks, idx, sent = {}, [], 0, [0]
    sent_lock = threading.Lock()

    # 权限矩阵里 403 往往是"本该拒绝"的正确表现，不是防护层拦截。
    # 默认把 403 从停手清单里摘掉，只保留 429/503；要改回严格模式请显式设 stop_on_403=true。
    matrix_stop = [s for s in plan["stop_on_block"] if s != 403]
    if plan.get("stop_on_403"):
        matrix_stop = list(plan["stop_on_block"])

    for ident in identities:
        row = str(ident.get("label") or ident.get("name"))
        for obj in objects:
            col = str(obj.get("label") or obj.get("value"))
            raw = plan["request_template"].replace("{{OBJ}}", str(obj.get("value", "")))
            raw = raw.replace("{{HDR}}", _hdr_block(ident.get("headers")))
            decoded = urllib.parse.unquote(raw)
            hits = check_destructive(raw + "\n" + decoded, plan["deny_patterns"])
            cell = {"row": row, "col": col, "status": "-", "verdict": dps.UNKNOWN,
                    "flag": "", "evidence": "-", "note": ""}
            if hits:
                cell["note"] = "拒发 破坏性载荷：%s" % ",".join(hits[:3])
                cells[(row, col)] = cell
                continue
            try:
                req = parse_raw(raw)
                url = build_url(req, plan["scheme"])
            except Exception as exc:
                cell["note"] = "模板错误：%s" % exc
                cells[(row, col)] = cell
                continue
            if dry_run:
                cell["note"] = url
                cells[(row, col)] = cell
                continue
            idx += 1
            tasks.append((row, col, obj, raw, req, url, idx))

    def work(t):
        row, col, obj, raw, req, url, tidx = t
        if not pacer.wait():
            return (row, col), {"row": row, "col": col, "status": "-",
                                "verdict": dps.UNKNOWN, "flag": "", "evidence": "-",
                                "note": "未发送（防护中断）"}
        res = send(req, url, timeout=timeout, insecure=insecure,
                   legacy_tls=bool(plan.get("tls_legacy")))
        with sent_lock:
            sent[0] += 1
        safe = re.sub(r"[^\w\-.]", "_", "%s__%s" % (row, col))[:48]
        rq = outdir / ("%03d_%s.req" % (tidx, safe))
        rs = outdir / ("%03d_%s.resp" % (tidx, safe))
        dump_exchange(rq, rs, raw, url, res)
        cell = {"row": row, "col": col, "status": res["status"],
                "verdict": dps.classify_cell(res["status"]),
                "len": len(res["body"]), "sha256": digest(res["body"]),
                "evidence": "%s / %s" % (rq.name, rs.name),
                "flag": "", "note": "",
                "set_cookie": [v for k, v in (res.get("headers") or [])
                               if k.lower() == "set-cookie"]}
        owner = str(obj.get("owner") or "")
        cross = owner and row != owner and row not in ("admin", "管理员")
        if cross and cell["verdict"] == dps.ALLOW:
            cell["flag"] = "越权候选"
            cell["note"] = "对象 owner=%s，本行为 %s，却返回 2xx" % (owner, row)
        if res["status"] in matrix_stop:
            pacer.block()
        return (row, col), cell

    if tasks:
        with ThreadPoolExecutor(max_workers=pacer.threads) as ex:
            futs = {ex.submit(work, t): t for t in tasks}
            for fut in as_completed(futs):
                t = futs[fut]
                try:
                    key, cell = fut.result()
                except Exception as exc:
                    key = (t[0], t[1])
                    cell = {"row": t[0], "col": t[1], "status": "-",
                            "verdict": dps.UNKNOWN, "flag": "", "evidence": "-",
                            "note": "%s: %s" % (type(exc).__name__, exc)}
                cells[key] = cell

    blocked = None
    stopped = None
    for (row, col), cell in cells.items():
        if cell.get("status") in matrix_stop:
            blocked, stopped = cell["status"], "%s×%s" % (row, col)
            break

    return {"name": plan["name"], "rows": rows, "cols": cols, "cells": cells,
            "requests": sent[0], "blocked": blocked, "stopped": stopped,
            "objects": objects, "identities": rows,
            "concurrency": pacer.snapshot()}


def report_matrix(result):
    lines = ["", "=== 权限矩阵：%s ===" % result["name"], ""]
    conc = result.get("concurrency") or {}
    if conc:
        lines.append("节奏：%s 线程 / %sms%s" % (
            conc.get("threads"), conc.get("delay_ms"),
            "；已触发防护，后续单线程 <6/分钟" if conc.get("blocked") else ""))
    cell_map = {(r, c): result["cells"][(r, c)] for r, c in result["cells"]}
    lines.append(dps.render_matrix(result["rows"], result["cols"], cell_map))
    lines.append("")
    flags = [c for c in result["cells"].values() if c.get("flag")]
    if flags:
        lines.append("越权候选（2xx 且对象 owner 与本行主体不符）：")
        for c in flags:
            lines.append("  [%s × %s] status=%s  %s" % (c["row"], c["col"], c["status"], c["note"]))
            lines.append("              证据 %s" % c["evidence"])
    else:
        lines.append("越权候选：无（对角线允许、非对角线拒绝，是权限正常的表现）")
    sc = {k: v for k, v in ((c["row"], c.get("set_cookie")) for c in result["cells"].values())}
    issued = {k: v for k, v in sc.items() if v}
    if issued:
        lines.append("")
        lines.append("签发会话的上下文：%s" % "、".join(sorted(issued)))
    if result["blocked"]:
        conc = result.get("concurrency") or {}
        tail = ("已进入单线程 <6/分钟降级，达到补发上限后停止"
                if conc.get("blocked") else "已进入降级模式")
        lines.append("")
        lines.append("!! 触发防护（%s，%s）——%s" % (result["blocked"], result["stopped"], tail))
    lines.append("")
    lines.append("判定纪律：2xx 只说明服务端执行了动作，不等于越权；")
    lines.append("          必须确认返回对象确实属于他人（比对 owner 字段），并排除该接口本就公开。")
    return "\n".join(lines)


def run_sequence(plan, outdir, dry_run=False, insecure=True, timeout=20):
    r"""状态机差分：正常顺序 / 跳步 / 重放 / 跨会话。

    比给每个参数追引号更能发现业务 0day：缺陷常在"步骤之间的信任"，
    而不在单个参数的类型处理上。
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    spec = plan.get("sequence") or {}
    steps = {s["label"]: s for s in (spec.get("steps") or [])}
    variants = spec.get("variants") or []
    identities = spec.get("identities") or {}
    if not steps or not variants:
        raise SystemExit("[error] sequence 模式需要 plan.sequence.steps 与 plan.sequence.variants")
    limiter = RateLimiter(plan["rate_limit_per_min"])
    runs, idx, blocked = [], 0, None

    for variant in variants:
        vlabel = str(variant.get("label") or "变体")
        records, variables = [], {}
        for entry in variant.get("steps") or []:
            if isinstance(entry, str):
                name, ident = entry, None
            else:
                name, ident = entry.get("step"), entry.get("identity")
            step = steps.get(name)
            if not step:
                records.append({"label": name, "status": "-", "note": "未知步骤"})
                continue
            ident = ident or step.get("identity")
            raw = step.get("raw") or step.get("request_template") or ""
            for k, v in variables.items():
                raw = raw.replace("{{%s}}" % k, str(v))
            if "{{HDR}}" in raw:
                raw = raw.replace("{{HDR}}", _hdr_block((identities.get(ident) or {}).get("headers")))
            rec = {"label": "%s/%s" % (vlabel, name), "step": name, "identity": ident}
            decoded = urllib.parse.unquote(raw)
            hits = check_destructive(raw + "\n" + decoded, plan["deny_patterns"])
            if hits:
                rec.update({"status": "-", "note": "拒发：%s" % ",".join(hits[:3]), "sha": "-"})
                records.append(rec)
                continue
            if "{{" in raw:
                rec.update({"status": "-", "sha": "-",
                            "note": "仍有未展开的占位符（缺前序变量）：%s"
                                    % ",".join(sorted(set(re.findall(r"\{\{(\w+)\}\}", raw))))})
                records.append(rec)
                continue
            try:
                req = parse_raw(raw)
                url = build_url(req, plan["scheme"])
            except Exception as exc:
                rec.update({"status": "-", "sha": "-", "note": "模板错误：%s" % exc})
                records.append(rec)
                continue
            if dry_run:
                rec.update({"status": "(dry)", "sha": "-", "note": url})
                records.append(rec)
                continue
            limiter.wait()
            res = send(req, url, timeout=timeout, insecure=insecure,
                       legacy_tls=bool(plan.get("tls_legacy")))
            idx += 1
            safe = re.sub(r"[^\w\-.]", "_", "%s_%s" % (vlabel, name))[:48]
            rq = outdir / ("%03d_%s.req" % (idx, safe))
            rs = outdir / ("%03d_%s.resp" % (idx, safe))
            dump_exchange(rq, rs, raw, url, res)
            text = res["body"].decode("utf-8", errors="replace")
            rec.update({"status": res["status"], "len": len(res["body"]),
                        "sha": digest(res["body"]), "evidence": "%s / %s" % (rq.name, rs.name),
                        "note": ""})
            for var, pat in (step.get("extract") or {}).items():
                got = dps.extract_var(pat, text)
                if got:
                    variables[var] = got
                    rec["extracted"] = "%s=%s" % (var, got[:24])
            records.append(rec)
            if res["status"] in plan["stop_on_block"]:
                blocked = res["status"]
                break
        runs.append({"variant": vlabel, "steps": records, "note": variant.get("note", ""),
                     "fingerprint": dps.sequence_fingerprint(records)})
        if blocked:
            break

    return {"name": plan["name"], "runs": runs, "requests": idx, "blocked": blocked,
            "concurrency": {"threads": 1,
                            "delay_ms": int(round(60000.0 / max(1, plan["rate_limit_per_min"]))),
                            "blocked": bool(blocked), "post_block": 0, "stopped": False,
                            "note": "状态机顺序执行，不并发"}}


def report_sequence(result):
    lines = ["", "=== 状态机差分：%s ===" % result["name"], ""]
    lines.append("节奏：状态机顺序执行（不并发）")
    normal = next((r for r in result["runs"] if "正常" in r["variant"]), result["runs"][0])
    lines.append("基准变体：%s ｜ 指纹 %s" % (normal["variant"], normal["fingerprint"][:120]))
    lines.append("")
    for run in result["runs"]:
        same = run["fingerprint"] == normal["fingerprint"]
        tag = "与基准一致" if same else "与基准不同"
        lines.append("  [%s] %s" % (tag, run["variant"]))
        if run.get("note"):
            lines.append("      说明：%s" % run["note"])
        for s in run["steps"]:
            extra = ("  " + s.get("note", "")) if s.get("note") else ""
            ex = ("  抽到 %s" % s["extracted"]) if s.get("extracted") else ""
            lines.append("      %-28s status=%-5s len=%-6s%s%s"
                         % (s["label"], s.get("status"), s.get("len", "-"), ex, extra))
    lines.append("")
    if result["blocked"]:
        lines.append("!! 触发防护 %s，已在中断处停止" % result["blocked"])
        lines.append("")
    diff_variants = [r["variant"] for r in result["runs"] if r["fingerprint"] != normal["fingerprint"]]
    if diff_variants:
        lines.append("与基准顺序产生不同业务状态：%s" % "、".join(diff_variants))
        lines.append("→ 逐条按 §10 立假设：是流程跳跃被接受，还是仅仅错误码不同？")
    else:
        lines.append("所有变体与基准顺序在状态码/长度/正文哈希上一致 → 该状态机假设证伪（在本次样本内）。")
    lines.append("")
    lines.append("纪律：'重放/跳步被接受'必须以业务副作用为 oracle（新凭证、新绑定、新记录），")
    lines.append("      仅 2xx 不足以定论；跨会话变体必须确认两个会话确实属于不同主体。")
    return "\n".join(lines)


def _analyze(plan, records, blocked, stopped):
    """基线取自标了 baseline 的行；无则取第一行。

    两级判定：
      传输层 —— 状态码 / 净长度 / 耗时 / 标记
      语义层 —— JSON 结构差分（当 plan.semantic 或 --mode semantic 时启用）
    触达断言不满足时，本轮所有结论降级为「无效（未证明进入目标业务路径）」，
    而不是「无差分」—— 那是这轮最容易把"没打进去"写成"已排除"的地方。
    """
    base = [r for r in records if r.get("is_baseline")]
    if not base:
        base = [r for r in records if r["verdict"] != "拒发" and r["status"] not in ("-",)]
        base = base[:1]

    semantic_spec = plan.get("semantic") if isinstance(plan.get("semantic"), dict) else None
    want_semantic = bool(semantic_spec) or bool(plan.get("_force_semantic"))
    ignore_paths = (semantic_spec or {}).get("ignore_paths") or []
    watch_paths = (semantic_spec or {}).get("watch_paths") or []

    band = {"n": len(base), "status": None, "len_min": 0, "len_max": 0,
            "len_mid": 0, "ms_mid": 0, "sha": set(), "markers": set(),
            "payload_len": 0}
    if base:
        lens = [r["len"] for r in base]
        mss = [r["ms"] for r in base]
        band.update({
            "status": base[0]["status"],
            "len_min": min(lens), "len_max": max(lens),
            "len_mid": median(lens), "ms_mid": median(mss),
            "sha": set(r["sha256"] for r in base),
            "markers": set(m for r in base for m in r["markers"].split(",") if m),
            "payload_len": len(base[0]["payload"]),
        })

    spread = max(0, band["len_max"] - band["len_min"])
    invalid = bool(base) and (band["status"] in (0, None) or all(r.get("error") for r in base))

    reach_ok, reach_problems = (True, [])
    if base and not invalid:
        reach_ok, reach_problems = dps.check_reachability(plan.get("reachability"), base[0])

    base_json = base_obj = None
    if want_semantic and base and not invalid:
        base_obj, base_why = dps.try_parse_json(base[0].get("body") or b"", base[0].get("headers"))
        if base_obj is None:
            reach_problems = list(reach_problems) + ["语义差分不可用：基线%s" % base_why]

    for r in records:
        if r["verdict"] in ("拒发", "模板错误", "未发送"):
            continue
        if invalid:
            r["verdict"] = "无效（基线不可达）"
            r["delta_len"] = 0
            r["delta_ms"] = 0
            r["reason"] = r.get("reason") or "基线连接失败，本轮差分结论作废"
            continue
        if not reach_ok:
            r["verdict"] = "无效（未证明进入目标业务路径）"
            r["delta_len"] = 0
            r["delta_ms"] = 0
            r["reason"] = "；".join(reach_problems)
            continue
        if r.get("is_baseline") or not base:
            r["verdict"] = "基线"
            r["delta_len"] = 0
            r["delta_ms"] = 0
            r["net_len"] = 0
            r["semantic"] = "基线"
            continue
        reasons = []
        r["delta_len"] = r["len"] - band["len_mid"]
        r["delta_ms"] = int(r["ms"] - band["ms_mid"])
        if r["status"] != band["status"]:
            reasons.append("状态码 %s≠%s" % (r["status"], band["status"]))
        # 净长度差：扣掉"载荷自身被回显"造成的长度变化，否则任何变长载荷都会假阳性
        r["net_len"] = r["delta_len"] - (len(r["payload"]) - band["payload_len"])
        if abs(r["net_len"]) > spread:
            reasons.append("净长度 %+d（原始 Δlen=%+d，基线波动带 ±%d）"
                           % (r["net_len"], r["delta_len"], spread))
        if r["ms"] > band["ms_mid"] + plan["time_band_ms"]:
            reasons.append("耗时 %+dms 超带宽 %dms" % (r["delta_ms"], plan["time_band_ms"]))
        hit = [m for m in r["markers"].split(",") if m and m not in band["markers"]]
        if hit:
            reasons.append("命中标记 %s" % ",".join(hit))
        if r.get("error"):
            reasons.append("连接层错误：%s" % r["error"])

        sem_changes = []
        if want_semantic and base_obj is not None:
            obj, why = dps.try_parse_json(r.get("body") or b"", r.get("headers"))
            if obj is None:
                r["semantic"] = "N/A"
                if reasons:
                    r["semantic_note"] = why
            else:
                sem_changes = dps.structural_diff(base_obj, obj, ignore_paths, watch_paths)
                r["semantic"] = "DIFF" if sem_changes else "SAME"
        r["semantic_changes"] = "; ".join(
            "%s %s%s" % (c["path"], c["change"],
                         (" %s→%s" % (c.get("before"), c.get("after")))
                         if c.get("before") is not None and c.get("after") is not None else "")
            for c in sem_changes[:12])

        if reasons:
            r["verdict"] = "差分"
        elif sem_changes:
            r["verdict"] = "语义差分"
            reasons.append("传输层四维一致，但 JSON 结构有 %d 处变化" % len(sem_changes))
        else:
            r["verdict"] = "无差分"
        r["reason"] = "；".join(reasons)

    return {
        "name": plan["name"],
        "invalid": invalid,
        "reachability": {"checked": bool(base) and not invalid,
                         "ok": bool(reach_ok),
                         "problems": list(reach_problems)},
        "semantic": {"enabled": want_semantic,
                     "baseline_is_json": base_obj is not None,
                     "ignore_paths": list(ignore_paths),
                     "watch_paths": list(watch_paths)},
        "set_cookie": {r["label"]: [v for k, v in (r.get("headers") or [])
                                    if k.lower() == "set-cookie"]
                       for r in records if not r.get("is_baseline")},
        "band": {"baseline_status": band["status"], "baseline_len": band["len_mid"],
                 "len_spread": spread, "baseline_ms": band["ms_mid"],
                 "baseline_repeats": band["n"]},
        "records": records,
        "blocked_status": blocked,
        "stopped_at": stopped,
    }


COLS = ["label", "payload", "status", "len", "delta_len", "net_len", "ms",
        "delta_ms", "sha256", "markers", "semantic", "semantic_changes",
        "verdict", "reason", "evidence"]


def write_csv(path, records):
    with io.open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(dict((c, r.get(c, "")) for c in COLS))


def report(result, quiet=False):
    b = result["band"]
    lines = []
    lines.append("=== 差分探针：%s ===" % result["name"])
    conc = result.get("concurrency") or {}
    if conc:
        lines.append("节奏：%s 线程 / %sms%s" % (
            conc.get("threads"), conc.get("delay_ms"),
            "；已触发防护，后续单线程 <6/分钟" if conc.get("blocked") else ""))
    lines.append("基线：status=%s len=%s（波动带 ±%d）ms=%s 重复=%d" % (
        b["baseline_status"], b["baseline_len"], b["len_spread"],
        b["baseline_ms"], b["baseline_repeats"]))
    if result.get("invalid"):
        lines.append("!! 基线不可达（status=%s）——本轮全部结论作废，先修网络/会话再重跑。"
                     % b["baseline_status"])
    reach = result.get("reachability") or {}
    if reach.get("checked") and not reach.get("ok"):
        lines.append("!! 触达断言不满足 —— 本轮结论一律是「无效（未证明进入目标业务路径）」，"
                     "不是「无差分」。先把基线调到能进入目标业务分支：")
        for p in reach.get("problems") or []:
            lines.append("     - %s" % p)
    sem = result.get("semantic") or {}
    if sem.get("enabled"):
        if sem.get("baseline_is_json"):
            lines.append("语义层：已启用（忽略 %s ／ 只观察 %s）"
                         % ("、".join(sem.get("ignore_paths") or []) or "（未指定）",
                            "、".join(sem.get("watch_paths") or []) or "（全部路径）"))
        else:
            lines.append("语义层：已请求但基线不是 JSON —— 本轮只有传输层结论。")
    if result["blocked_status"]:
        conc = result.get("concurrency") or {}
        tail = ("已进入单线程 <6/分钟降级，达到补发上限后停止"
                if conc.get("blocked") else "已进入降级模式")
        lines.append("!! 命中防护层 %s（在 %s 处）——%s；该目标标记为「已触发防护」"
                     % (result["blocked_status"], result["stopped_at"], tail))
    diffs = [r for r in result["records"] if r["verdict"] == "差分"]
    sems = [r for r in result["records"] if r["verdict"] == "语义差分"]
    voids = [r for r in result["records"] if r["verdict"].startswith("无效")]
    other = [r for r in result["records"]
             if r["verdict"].startswith("未发送") or r["verdict"] in ("拒发", "模板错误", "错误")]
    sent = [r for r in result["records"] if r not in other]
    lines.append("")
    if not sent:
        lines.append("dry-run：未发送任何请求 —— 差分结论不适用（不是「无差分」）。")
    else:
        lines.append("差分行（%d 条，仅这些需要进上下文）：" % len(diffs))
        for r in diffs:
            lines.append("  [%-14s] status=%-4s 净Δlen=%-6s Δms=%-6s  %s" % (
                r["label"], r["status"], r.get("net_len", ""), r["delta_ms"], r["reason"]))
        if sems:
            lines.append("")
            lines.append("语义差分行（%d 条，传输层四维一致但 JSON 结构变了）：" % len(sems))
            for r in sems:
                lines.append("  [%-14s] %s" % (r["label"], r.get("semantic_changes") or ""))
        sc = result.get("set_cookie") or {}
        issued = {k: v for k, v in sc.items() if v}
        if issued:
            lines.append("")
            lines.append("响应签发 Cookie（会话是否被新签发，是身份类 oracle 的关键一环）：")
            for k, v in issued.items():
                lines.append("  [%-14s] %s" % (k, "; ".join(x[:80] for x in v[:2])))
        if not diffs and not sems:
            if reach.get("checked") and not reach.get("ok"):
                lines.append("  （不适用）—— 触达断言未通过，本轮不产生「无差分」结论。")
            else:
                lines.append("  （无）—— 全部载荷与基线在状态码/长度/耗时/标记四个维度上无差异"
                             + ("；语义层同样无变化" if sem.get("baseline_is_json") else ""))
        if voids:
            lines.append("")
            lines.append("无效行（%d 条，未证明进入目标业务路径 —— 不得当作「已排除」）：" % len(voids))
            for r in voids[:6]:
                lines.append("  [%-14s] %s" % (r["label"], r["reason"]))
    if other:
        lines.append("")
        lines.append("未发送（%d 条）：" % len(other))
        for r in other:
            lines.append("  [%-14s] %s  %s" % (r["label"], r["verdict"], r["reason"]))
    if not quiet:
        lines.append("")
        lines.append("判定指引：有差分行 → 按 §10 立假设并扩大样本；无差分且控制变量齐全 → 该假设证伪。")
        lines.append("净Δlen = 原始长度差 − 载荷自身长度差（抵消载荷被回显的干扰）。")
    return "\n".join(lines)


def main(argv=None):
    global PROXY, ALLOW_DESTRUCTIVE
    ap = argparse.ArgumentParser(description="差分探针 harness")
    ap.add_argument("--plan", required=True, help="plan JSON 路径")
    ap.add_argument("--out", default=None, help="证据输出目录（默认 diffprobe\\_runs\\<name>）")
    ap.add_argument("--dry-run", action="store_true", help="只渲染不发送")
    ap.add_argument("--proxy", default=None,
                    help="出站代理，如 http://127.0.0.1:7897（覆盖 plan 的 proxy 字段）")
    ap.add_argument("--mode", choices=["single", "paired", "semantic", "matrix", "sequence"],
                    default="single",
                    help="single=与基线比（默认）；paired=A/B 两发互比；semantic=强制 JSON 语义差分；"
                         "matrix=多身份×多对象权限矩阵；sequence=状态机差分（跳步/重放/跨会话）")
    ap.add_argument("--allow-destructive", action="store_true",
                    help="放行破坏性载荷（默认拒发；仅在明确授权且可回滚时使用）")
    ap.add_argument("--insecure", action="store_true", default=True)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--threads", type=int, default=None,
                    help="并发线程数（默认 8；1=单线程）")
    ap.add_argument("--delay-ms", type=int, default=None,
                    help="每个 worker 的请求间隔毫秒（默认 50）")
    ap.add_argument("--sequential", action="store_true",
                    help="强制单线程（计时敏感/状态机自动生效）")
    ap.add_argument("--block-delay-s", type=float, default=10.0,
                    help="触发防护后的串行间隔秒（默认 10 ⇒ <6/分钟）")
    ap.add_argument("--max-after-block", type=int, default=20,
                    help="触发防护后最多补发条数（默认 20），超过即停")
    args = ap.parse_args(argv)

    plan = load_plan(args.plan, args.mode)
    PROXY = args.proxy or plan.get("proxy") or None
    if args.allow_destructive:
        ALLOW_DESTRUCTIVE = True
        plan["deny_patterns"] = []
    if args.mode == "semantic":
        plan["_force_semantic"] = True

    # 并发解析：CLI > plan > 旧 rate_limit_per_min（显式时串行）> 默认 8/50ms。
    threads = args.threads
    delay_ms = args.delay_ms
    if args.sequential:
        threads = 1
    if threads is None:
        threads = plan.get("threads")
    if delay_ms is None:
        delay_ms = plan.get("delay_ms")
    if threads is None:
        if plan.get("_rate_explicit"):
            threads = 1
            if delay_ms is None:
                delay_ms = 60000.0 / max(1, plan["rate_limit_per_min"])
        else:
            threads = 8
    if delay_ms is None:
        delay_ms = 50
    threads = max(1, int(threads))
    if args.mode == "sequence" or _is_timing_sensitive(plan, args.mode):
        threads = 1
    pacer = Pacer(threads=threads, delay_ms=delay_ms,
                  block_delay_s=args.block_delay_s,
                  max_after_block=args.max_after_block)

    if args.mode == "paired":
        outdir = Path(args.out) if args.out else (
            HERE / "_runs" / re.sub(r"[^\w\-.]", "_", plan["name"]))
        result = run_pairs(plan, outdir, dry_run=args.dry_run,
                           insecure=args.insecure, timeout=args.timeout, pacer=pacer)
        print(report_pairs(result))
        if not args.dry_run:
            p = outdir / "pairs.csv"
            with io.open(p, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=PAIR_COLS, extrasaction="ignore")
                w.writeheader()
                for r in result["pairs"]:
                    w.writerow(dict((c, r.get(c, "")) for c in PAIR_COLS))
            print("")
            print("落盘：%s" % p)
            print("raw 请求/响应：%s" % outdir)
        return 1 if result["blocked"] else 0

    if args.mode == "matrix":
        outdir = Path(args.out) if args.out else (
            HERE / "_runs" / re.sub(r"[^\w\-.]", "_", plan["name"]))
        result = run_matrix(plan, outdir, dry_run=args.dry_run,
                            insecure=args.insecure, timeout=args.timeout, pacer=pacer)
        print(report_matrix(result))
        if not args.dry_run:
            p = outdir / "matrix.json"
            with io.open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps({
                    "name": result["name"], "rows": result["rows"], "cols": result["cols"],
                    "cells": [dict(v, row=k[0], col=k[1]) for k, v in result["cells"].items()],
                    "requests": result["requests"], "blocked": result["blocked"],
                }, ensure_ascii=False, indent=2) + "\n")
            print("")
            print("落盘：%s" % p)
            print("raw 请求/响应：%s" % outdir)
        return 1 if result["blocked"] else 0

    if args.mode == "sequence":
        outdir = Path(args.out) if args.out else (
            HERE / "_runs" / re.sub(r"[^\w\-.]", "_", plan["name"]))
        result = run_sequence(plan, outdir, dry_run=args.dry_run,
                              insecure=args.insecure, timeout=args.timeout)
        print(report_sequence(result))
        if not args.dry_run:
            p = outdir / "sequence.json"
            with io.open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            print("")
            print("落盘：%s" % p)
            print("raw 请求/响应：%s" % outdir)
        return 1 if result["blocked"] else 0

    # 归一化 payloads：标 baseline 的第一条作为基线重复发送
    items = []
    base_item = None
    for it in plan["payloads"]:
        if isinstance(it, str):
            it = {"label": it, "value": it}
        if base_item is None and it.get("baseline"):
            base_item = it
        items.append(it)
    if base_item is None:
        base_item = items[0]
        base_item["baseline"] = True

    repeats = max(1, int(plan["baseline_repeat"]))
    expanded = []
    for k in range(repeats):
        d = dict(base_item)
        d["label"] = "baseline#%d" % (k + 1)
        d["is_baseline"] = True
        expanded.append(d)
    for it in items:
        if it is base_item:
            continue
        expanded.append(it)
    plan["payloads"] = expanded

    outdir = Path(args.out) if args.out else (HERE / "_runs" / re.sub(r"[^\w\-.]", "_", plan["name"]))
    result = run(plan, outdir, dry_run=args.dry_run, insecure=args.insecure,
                 timeout=args.timeout, pacer=pacer)

    print(report(result))
    if not args.dry_run:
        csvp = outdir / "diffs.csv"
        write_csv(csvp, result["records"])
        jsp = outdir / "result.json"
        # 响应正文只留在 raw .resp 里：result.json 只保留索引字段，避免证据文件重复膨胀
        for rec in result["records"]:
            rec.pop("body", None)
            rec.pop("headers", None)
        with io.open(jsp, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        print("")
        print("落盘：%s" % csvp)
        print("落盘：%s" % jsp)
        print("raw 请求/响应：%s" % outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
