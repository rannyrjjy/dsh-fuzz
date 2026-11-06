#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fuzz_ops.py - planner / runner / verdict layer over diffprobe.

Read-only by default. The packet engine is always diffprobe; this script only
builds plans, harvests typed values, invokes diffprobe and classifies results.

Usage:
  python engine/fuzz/fuzz_ops.py --spec spec.json
  python engine/fuzz/fuzz_ops.py harvest  --response @resp.json --target demo
  python engine/fuzz/fuzz_ops.py doctor

Spec actions: harvest, plan, run, verdict, bizmap, doctor.
"""
from __future__ import annotations

import csv
import io
import itertools
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent          # <repo>/engine/fuzz
FUZZ = HERE
# Engine root: <repo>/engine in this package; <workspace>/作战工具 in a workspace
# install. Both layouts keep diffprobe/ and payloadsets/ as siblings of fuzz/.
ENGINE_ROOT = Path(os.environ.get("DSH_FUZZ_ENGINE") or HERE.parent).resolve()
ENGINE = ENGINE_ROOT / "diffprobe" / "diffprobe.py"
PAYLOADS = ENGINE_ROOT / "payloadsets"
# Workspace: base for @relative paths, the diffprobe cwd, and evidence output.
ROOT = Path(os.environ.get("DSH_FUZZ_WORKSPACE") or Path.cwd()).resolve()
EVIDENCE = ROOT / os.environ.get("DSH_FUZZ_EVIDENCE_DIR", "漏洞记录")
# Runtime state (plans/seeds/runs). Defaults to the package dir when it already
# carries a plans/ folder (workspace install), otherwise <workspace>/.dsh-fuzz.
STATE = Path(os.environ.get("DSH_FUZZ_STATE") or
             (FUZZ if (FUZZ / "plans").is_dir() else ROOT / ".dsh-fuzz"))
PLANS = STATE / "plans"
SEEDS = STATE / "seeds"
RUNS = STATE / "runs"

WORD = re.compile(r"[a-z0-9][a-z0-9_.-]*")
PHONE = re.compile(r"^1[3-9]\d{9}$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUM = re.compile(r"^-?\d{1,19}$")
AMOUNT = re.compile(r"^-?\d+(?:\.\d+)?$")
TOKEN = re.compile(r"^[A-Za-z0-9_\-\.=+/]{20,}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ID_HINT = re.compile(r"(id|uid|user|order|no|number|phone|mobile|tel|file|tenant|org|shop|account|name|email|code|key)", re.I)


def out(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def read_arg(value):
    if value is None:
        return None
    if isinstance(value, str) and value.startswith("@"):
        p = Path(value[1:])
        if not p.is_absolute():
            p = ROOT / p
        return p.read_text(encoding="utf-8", errors="replace")
    return value


def load_json_arg(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    text = read_arg(value)
    return json.loads(text)


_TAG_SEQ = itertools.count(1)

# 沙箱把 *_PROXY 注入成 127.0.0.1:9 哨兵（死端口），照抄会全量失败。
DEAD_PROXY = "http://127.0.0.1:9"


def now_tag() -> str:
    """秒级精度会同秒撞名。

    实测：同一秒内并发发三次 plan，输出名都是 <秒>-<kind>-<i>.json，
    后发的直接覆盖先发的（plan 丢失、证据链断掉）。
    改为 毫秒 + 进程内序号，再由 unique_path() 兜底。
    """
    ms = (time.time_ns() // 1_000_000) % 1000
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{ms:03d}-{next(_TAG_SEQ):03d}"


def unique_path(directory: Path, filename: str) -> Path:
    """同名加序号，绝不覆盖已存在的文件。"""
    p = directory / filename
    if not p.exists():
        return p
    stem, suffix = p.stem, p.suffix
    for n in range(2, 1000):
        q = directory / f"{stem}-{n}{suffix}"
        if not q.exists():
            return q
    return directory / f"{stem}-{os.getpid()}{suffix}"


def resolve_proxy(spec: dict, config_path: Path | None = None) -> str | None:
    """出站代理解析顺序：spec > FUZZ_PROXY > 工作区默认文件 > 环境 *_PROXY。

    环境里的 *_PROXY 跳过沙箱死端口哨兵 127.0.0.1:9。
    工作区默认文件（作战工具\\fuzz\\proxy.json）是 DSH bundle 侧唯一能拿到的入口：
    bundle 的 fuzz 工具没有 proxy 入参，会话里无法临时传。
    """
    p = str(spec.get("proxy") or "").strip()
    if p:
        return p
    p = str(os.environ.get("FUZZ_PROXY") or "").strip()
    if p:
        return p
    cfg = config_path if config_path is not None else (FUZZ / "proxy.json")
    try:
        if cfg and Path(cfg).exists():
            data = json.loads(Path(cfg).read_text(encoding="utf-8-sig"))
            p = str(data.get("proxy") or "").strip()
            if p:
                return p
    except Exception:  # noqa: BLE001 - 配置文件坏了不该拖垮整个计划流程
        pass
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        v = str(os.environ.get(var) or "").strip()
        if not v:
            continue
        if v.rstrip("/").lower() == DEAD_PROXY:
            continue
        return v
    return None


# ---------------------------------------------------------------- raw HTTP

def parse_raw(text: str) -> dict:
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request line")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("bad request line")
    method, path = parts[0], parts[1]
    headers: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return {"method": method.upper(), "path": path, "headers": headers, "body": body}


def raw_text(req: dict) -> str:
    lines = [f"{req['method']} {req['path']} HTTP/1.1"]
    for k, v in req["headers"]:
        lines.append(f"{k}: {v}")
    lines.append("")
    if req.get("body"):
        lines.append(req["body"])
    return "\n".join(lines)


def header(req: dict, name: str) -> str | None:
    for k, v in req["headers"]:
        if k.lower() == name.lower():
            return v
    return None


def is_json(req: dict) -> bool:
    ct = (header(req, "content-type") or "").lower()
    if "json" in ct:
        return True
    body = (req.get("body") or "").strip()
    return body.startswith("{") or body.startswith("[")


def query_pairs(path: str) -> list[tuple[str, str]]:
    if "?" not in path:
        return []
    q = path.split("?", 1)[1]
    return urllib.parse.parse_qsl(q, keep_blank_values=True)


def set_query(path: str, name: str, placeholder: str = "{{PE}}") -> str:
    base, _, q = path.partition("?")
    pairs = urllib.parse.parse_qsl(q, keep_blank_values=True)
    found = False
    out_pairs = []
    for k, v in pairs:
        if k == name:
            out_pairs.append((k, placeholder))
            found = True
        else:
            out_pairs.append((k, v))
    if not found:
        out_pairs.append((name, placeholder))
    qs = "&".join("%s=%s" % (k, v) for k, v in out_pairs)
    return base + ("?" + qs if qs else "")


def set_json(req: dict, name: str, placeholder: str = "{{P}}") -> str:
    try:
        obj = json.loads(req["body"] or "{}")
    except Exception:
        return raw_text(req)
    if not isinstance(obj, dict):
        return raw_text(req)
    obj[name] = placeholder
    req2 = dict(req)
    req2["body"] = json.dumps(obj, ensure_ascii=False)
    return raw_text(req2)


def append_fragment(req: dict, placeholder: str = "{{P}}") -> str:
    if is_json(req):
        body = (req.get("body") or "{}").rstrip()
        if body.endswith("}"):
            body = body[:-1] + placeholder + "}"
        else:
            body = body + placeholder
        req2 = dict(req)
        req2["body"] = body
        return raw_text(req2)
    req2 = dict(req)
    if req["method"] in ("POST", "PUT", "PATCH"):
        req2["body"] = (req.get("body") or "") + placeholder
    else:
        req2["path"] = req["path"] + placeholder
    return raw_text(req2)


def request_params(req: dict) -> list[str]:
    names = [k for k, _ in query_pairs(req["path"])]
    if is_json(req):
        try:
            obj = json.loads(req["body"] or "{}")
            if isinstance(obj, dict):
                names += list(obj.keys())
        except Exception:
            pass
    elif req.get("body"):
        names += [k for k, _ in urllib.parse.parse_qsl(req["body"], keep_blank_values=True)]
    seen = set()
    out_names = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out_names.append(n)
    return out_names


def param_value(req: dict, name: str) -> str | None:
    for k, v in query_pairs(req["path"]):
        if k == name:
            return v
    if is_json(req):
        try:
            obj = json.loads(req["body"] or "{}")
            if isinstance(obj, dict) and name in obj:
                return str(obj[name])
        except Exception:
            pass
    elif req.get("body"):
        for k, v in urllib.parse.parse_qsl(req["body"], keep_blank_values=True):
            if k == name:
                return v
    return None


def replace_param(req: dict, name: str) -> str:
    if any(k == name for k, _ in query_pairs(req["path"])):
        req2 = dict(req)
        req2["path"] = set_query(req["path"], name)
        return raw_text(req2)
    if is_json(req):
        return set_json(req, name)
    if req.get("body"):
        req2 = dict(req)
        req2["body"] = re.sub(r"(%s=)[^&]*" % re.escape(name), r"\1{{PE}}", req["body"])
        return raw_text(req2)
    return append_fragment(req)


# ---------------------------------------------------------------- harvest

def classify_value(value) -> str:
    if isinstance(value, bool):
        return "bool"
    s = str(value).strip()
    if not s:
        return "empty"
    if PHONE.match(s):
        return "phone"
    if EMAIL.match(s):
        return "email"
    if UUID.match(s):
        return "uuid"
    if NUM.match(s):
        return "numeric_id" if len(s) >= 4 else "number"
    if AMOUNT.match(s):
        return "amount"
    if TOKEN.match(s):
        return "token"
    if re.match(r"^[A-Za-z_\-]{1,24}$", s):
        return "enum"
    return "string"


def mask(value: str) -> str:
    s = str(value)
    if PHONE.match(s):
        return s[:3] + "****" + s[-4:]
    if EMAIL.match(s):
        a, _, b = s.partition("@")
        return (a[:1] + "***@" + b)
    if len(s) > 12:
        return s[:4] + "…" + s[-2:]
    return s


def walk_json(obj, path="", out_values=None):
    if out_values is None:
        out_values = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            walk_json(v, f"{path}.{k}" if path else k, out_values)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            walk_json(v, f"{path}[{i}]", out_values)
    else:
        out_values.append((path, obj))
    return out_values


def harvest(spec: dict) -> dict:
    response = read_arg(spec.get("response")) or ""
    if response.startswith("HTTP/"):
        response = response.partition("\n\n")[2] if "\n\n" in response else ""
    values = []
    fields = []
    try:
        obj = json.loads(response)
        for path, v in walk_json(obj):
            if isinstance(v, (str, int, float)) and str(v).strip():
                field = re.split(r"[.\[]", path)[-1]
                values.append({"value": str(v), "type": classify_value(v), "path": path, "field": field})
                if field and field not in fields:
                    fields.append(field)
    except Exception:
        for m in re.finditer(r"(?<!\d)(1[3-9]\d{9})(?!\d)", response):
            values.append({"value": m.group(1), "type": "phone", "path": "", "field": "phone"})
        for m in re.finditer(r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}(?![0-9a-fA-F])", response):
            values.append({"value": m.group(0), "type": "uuid", "path": "", "field": "uuid"})
        for m in re.finditer(r"(?<![\w-])(\d{4,19})(?![\w-])", response):
            values.append({"value": m.group(1), "type": "numeric_id", "path": "", "field": "id"})
    # dedupe
    seen = set()
    uniq = []
    for v in values:
        key = (v["value"], v["type"])
        if key not in seen:
            seen.add(key)
            uniq.append(v)
    uniq = uniq[:300]
    SEEDS.mkdir(parents=True, exist_ok=True)
    target = spec.get("target") or "adhoc"
    path = SEEDS / f"{target}-{now_tag()}.json"
    payload = {"source": spec.get("source") or "response", "values": uniq,
               "fields": fields, "count": len(uniq)}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    preview = [{"type": v["type"], "field": v["field"], "value": mask(v["value"]), "path": v["path"]}
               for v in uniq[:12]]
    types: dict[str, int] = {}
    for v in uniq:
        types[v["type"]] = types.get(v["type"], 0) + 1
    return {"ok": True, "summary": f"harvest {len(uniq)} values -> {path.name}",
            "data": {"seedsPath": str(path), "count": len(uniq), "types": types,
                     "fields": fields[:30], "preview": preview}}


# ---------------------------------------------------------------- plan

def load_set(name: str) -> dict:
    p = PAYLOADS / f"{name}.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def control_value(value: str, typ: str) -> str:
    if typ == "numeric_id":
        try:
            return str(int(value) + 1)
        except Exception:
            return "99999999"
    if typ == "phone":
        return "13800000000"
    if typ == "email":
        return "control@example.com"
    if typ == "uuid":
        return "00000000-0000-0000-0000-000000000000"
    return "control_value"


def name_score(field: str, param: str) -> float:
    f = (field or "").lower()
    p = (param or "").lower()
    if not f or not p:
        return 0.0
    if f == p:
        return 5.0
    if f in p or p in f:
        return 3.0
    ft = set(WORD.findall(f))
    pt = set(WORD.findall(p))
    if ft & pt:
        return 2.0
    return 0.0


def make_baseline(req: dict, param: str, existing: bool) -> str:
    if existing:
        v = param_value(req, param)
        return v if v is not None else ""
    return ""


def build_payloads(req: dict, param: str, existing: bool, kind: str,
                   seeds: list[dict], values: list[str]) -> list[dict]:
    payloads = []
    baseline = make_baseline(req, param, existing)
    payloads.append({"label": "baseline", "value": baseline, "baseline": True})
    if kind in ("chain", "idor"):
        for s in seeds[:4]:
            payloads.append({"label": "inject-" + s["type"], "value": str(s["value"])})
        if seeds:
            payloads.append({"label": "control", "value": control_value(str(seeds[0]["value"]), seeds[0]["type"])})
    else:
        for i, v in enumerate(values[:6], 1):
            payloads.append({"label": f"inject-{i}", "value": v})
        payloads.append({"label": "control", "value": "control_value"})
    return payloads


def _iter_pairs(obj):
    """把载荷集里的成对结构摊平成 (真, 假) 序列。"""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_pairs(v)
    elif isinstance(obj, (list, tuple)):
        if len(obj) >= 2 and all(isinstance(x, str) for x in obj[:2]):
            yield (obj[0], obj[1])
        else:
            for v in obj:
                yield from _iter_pairs(v)


def sqli_pairs() -> list[tuple[str, str]]:
    """成对布尔载荷：每组是 (真, 假)。

    差分探针只有在"同一注入点、真假两次"的前提下才能把长度抖动和注入区分开；
    载荷集里早就写了 pairs，之前没人用，plan 只能给出单发载荷 → 真假不可判。

    优先用 pairs_all（不含 SLEEP 等时间盲注，避免每组白等 3 秒）；
    没有 pairs_all 时只取 boolean/error 两组，时间组不进默认计划。
    """
    data = load_set("sqli")
    groups = []
    if data.get("pairs_all"):
        groups.append(data["pairs_all"])
    elif isinstance(data.get("pairs"), dict):
        groups.append({k: v for k, v in data["pairs"].items() if k in ("boolean", "error")})
    out: list[tuple[str, str]] = []
    for g in groups:
        out.extend((str(a), str(b)) for a, b in _iter_pairs(g))
    return out


def build_sqli_payloads(req: dict, param: str, existing: bool) -> list[dict]:
    """基线 + 成对真假 + 对照，合计 ≤10 发（单端点请求上限）。"""
    payloads = [{"label": "baseline", "value": make_baseline(req, param, existing), "baseline": True}]
    for i, (t, f) in enumerate(sqli_pairs()[:4], 1):
        payloads.append({"label": f"true-{i}", "value": t})
        payloads.append({"label": f"false-{i}", "value": f})
    payloads.append({"label": "control", "value": "control_value"})
    return payloads


def replace_path_segment(req: dict, segment: str) -> str:
    base, sep, query = req["path"].partition("?")
    parts = base.split("/")
    hit = False
    out_parts = []
    for part in parts:
        if part == segment:
            out_parts.append("{{P}}")
            hit = True
        else:
            out_parts.append(part)
    if not hit:
        raise ValueError(f"path segment not found: {segment}")
    req2 = dict(req)
    req2["path"] = "/".join(out_parts) + (sep + query if sep else "")
    return raw_text(req2)


def make_bypass_plan(spec: dict, req: dict, segment: str, verify: dict | None, index: int) -> dict:
    data = load_set("logic_bypass")
    values = [str(v) for v in (data.get("sets", {}).get("values") or [])][:8]
    template = replace_path_segment(req, segment)
    payloads = [
        {"label": "baseline", "value": segment, "baseline": True},
        {"label": "control", "value": "zzz-nonexistent-" + str(int(time.time()))[-5:]},
    ]
    for i, v in enumerate(values, 1):
        payloads.append({"label": f"bypass-{i}", "value": v})
    plan = {
        "name": f"{spec.get('target') or 'adhoc'}-bypass-{index}",
        "kind": "bypass",
        "scheme": spec.get("scheme") or "https",
        "request_template": template,
        "payloads": payloads,
        "rate_limit_per_min": int(spec.get("rate") or 12),
        "stop_on_block": [403, 429, 503],
        "markers": ["输入参数含有不允许的串", "暂时无法访问本站点", "securityIntercept", "Access Denied"],
        "meta": {"candidate": {"param": segment, "score": 3.0, "kind": "path-segment"},
                 "generated_at": now_tag(), "source": spec.get("source") or "manual"},
    }
    proxy = resolve_proxy(spec)
    if proxy:
        plan["proxy"] = proxy
    if verify:
        plan["verify"] = verify
    return plan


def make_plan(spec: dict, kind: str, req: dict, param: str, existing: bool,
              seeds: list[dict], values: list[str], verify: dict | None,
              candidate: dict, index: int) -> dict:
    if existing:
        template = replace_param(req, param)
        payloads = build_payloads(req, param, True, kind, seeds, values)
        if kind == "sqli":
            payloads = build_sqli_payloads(req, param, True)
    else:
        template = append_fragment(req)
        baseline = ""
        payloads = [{"label": "baseline", "value": baseline, "baseline": True}]
        if kind in ("massassign", "param"):
            for i, v in enumerate(values[:4], 1):
                frag = (",%s:%s" % (json.dumps(param), json.dumps(v)) if is_json(req)
                        else "&%s=%s" % (urllib.parse.quote(param), urllib.parse.quote(v)))
                payloads.append({"label": f"inject-{i}", "value": frag})
        else:
            for s in seeds[:3]:
                frag = (",%s:%s" % (json.dumps(param), json.dumps(str(s["value"]))) if is_json(req)
                        else "&%s=%s" % (urllib.parse.quote(param), urllib.parse.quote(str(s["value"]))))
                payloads.append({"label": "inject-" + s["type"], "value": frag})
        control = (",%s:%s" % (json.dumps(param), json.dumps("control")) if is_json(req)
                   else "&%s=control" % urllib.parse.quote(param))
        payloads.append({"label": "control", "value": control})

    plan = {
        "name": f"{spec.get('target') or 'adhoc'}-{kind}-{index}",
        "kind": kind,
        "scheme": spec.get("scheme") or "https",
        "request_template": template,
        "payloads": payloads,
        "rate_limit_per_min": int(spec.get("rate") or 12),
        "stop_on_block": [403, 429, 503],
        "markers": ["输入参数含有不允许的串", "暂时无法访问本站点", "securityIntercept",
                    "Access Denied", "Request blocked"],
        "meta": {"candidate": candidate, "generated_at": now_tag(),
                 "source": spec.get("source") or "manual"},
    }
    if verify:
        plan["verify"] = verify
    if kind == "race":
        plan["race"] = {"concurrency": int(spec.get("concurrency") or 8), "repeats": 1}
    proxy = resolve_proxy(spec)
    if proxy:
        plan["proxy"] = proxy
    return plan


def plan(spec: dict) -> dict:
    request_text = read_arg(spec.get("request"))
    if not request_text:
        return {"ok": False, "error": "request is required (raw HTTP text or @path)"}
    req = parse_raw(request_text)
    kind = spec.get("kind") or "chain"
    target = spec.get("target") or "adhoc"
    limit = int(spec.get("limit") or 6)
    params = list(spec.get("params") or [])
    if not params:
        params = [n for n in request_params(req) if ID_HINT.search(n)][:6]
        if not params:
            params = request_params(req)[:4]
    seeds_data = load_json_arg(spec.get("seeds")) or {}
    seeds = list(seeds_data.get("values") or [])

    candidates = []
    if kind in ("chain", "idor"):
        for param in params:
            for s in seeds:
                if s.get("type") not in ("numeric_id", "uuid", "phone", "email", "token", "string"):
                    continue
                sc = name_score(s.get("field", ""), param)
                if sc <= 0 and len(params) > 3:
                    continue
                candidates.append((sc, param, s))
    elif kind in ("massassign", "param"):
        names = params or (load_set("logic_massassign").get("sets", {}).get("fields", [])[:10])
        vals = (load_set("logic_massassign").get("sets", {}).get("values", ["admin", "1", "true"])
                if kind == "massassign" else ["1", "test"])
        for param in names:
            for v in vals[:3]:
                candidates.append((3.0, param, {"value": v, "type": "enum", "field": param, "path": ""}))
    elif kind in ("role", "tenant", "amount"):
        set_name = {"role": "logic_role", "tenant": "logic_tenant", "amount": "logic_amount"}[kind]
        data = load_set(set_name)
        fields = params or data.get("sets", {}).get("fields", [])[:6]
        vals = data.get("sets", {}).get("values", ["admin", "1", "0"])
        for param in fields:
            for v in vals[:4]:
                candidates.append((3.0, param, {"value": v, "type": "enum", "field": param, "path": ""}))
    elif kind in ("sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "xxe"):
        data = load_set(kind)
        vals: list[str] = []
        for group in (data.get("sets") or {}).values():
            if isinstance(group, list) and group:
                vals = [str(x) for x in group]
                break
        if not vals and kind != "sqli":
            return {"ok": False, "error": f"payload set {kind}.json has no values"}
        # 逐参数各出一份计划：一次调用 = 一组探测（原来只打 params[0]，其余参数全丢）
        names = params or request_params(req)[:4]
        if not names:
            return {"ok": False, "error": "no parameters found in request"}
        if kind == "sqli":
            for name in names:
                candidates.append((2.0, name, {"value": vals[0] if vals else "1",
                                               "type": "string", "field": name, "path": ""}))
        else:
            for name in names:
                for v in vals[:4]:
                    candidates.append((2.0, name, {"value": v, "type": "string", "field": name, "path": ""}))
    elif kind == "bypass":
        base_path = req["path"].partition("?")[0]
        segment = params[0] if params else next((p for p in reversed(base_path.split("/")) if p), "")
        if not segment:
            return {"ok": False, "error": "bypass needs a path segment (params[0] or a non-empty path segment)"}
        if segment not in base_path.split("/"):
            return {"ok": False, "error": f"path segment not found: {segment}"}
        candidates.append((3.0, segment, None))
    elif kind == "race":
        candidates.append((1.0, params[0] if params else "", None))
    else:
        return {"ok": False, "error": f"unsupported kind: {kind}"}

    candidates.sort(key=lambda x: -x[0])
    candidates = candidates[:limit]
    if not candidates:
        return {"ok": False, "error": "no candidates; check seeds/params/request"}

    PLAN_DIR = PLANS / target
    PLAN_DIR.mkdir(parents=True, exist_ok=True)
    verify = spec.get("verify")
    results = []
    for i, (sc, param, s) in enumerate(candidates, 1):
        existing = param_value(req, param) is not None
        values = [str(s["value"])] if s else []
        if kind == "bypass":
            plan_obj = make_bypass_plan(spec, req, param, verify, i)
        else:
            plan_obj = make_plan(spec, kind, req, param, existing, [s] if s else [], values, verify,
                                 {"param": param, "score": round(sc, 2),
                                  "seed": {k: s.get(k) for k in ("value", "type", "field", "path")} if s else None},
                                 i)
        path = unique_path(PLAN_DIR, f"{now_tag()}-{kind}-{i}.json")
        path.write_text(json.dumps(plan_obj, ensure_ascii=False, indent=2), encoding="utf-8")
        results.append({"path": str(path), "kind": kind, "param": param,
                        "requests": len(plan_obj["payloads"]),
                        "candidate": plan_obj["meta"]["candidate"]})

    dry = []
    if spec.get("dryRun"):
        for r in results:
            p = subprocess.run([sys.executable, str(ENGINE), "--plan", r["path"], "--dry-run"],
                               cwd=str(ROOT), capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=120)
            dry.append({"plan": r["path"], "ok": p.returncode == 0,
                        "tail": (p.stdout or p.stderr).strip().splitlines()[-1] if (p.stdout or p.stderr).strip() else ""})
    return {"ok": True,
            "summary": f"plan {kind}: {len(results)} plans, "
                       + (f"dry-run {sum(1 for d in dry if d['ok'])}/{len(dry)} ok" if dry else "not dry-run"),
            "data": {"plans": results, "dryRun": dry}}


# ---------------------------------------------------------------- run / verdict

def run_plan(plan_path: Path, spec: dict, out_dir: Path) -> dict:
    try:
        plan_obj = json.loads(plan_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"plan": str(plan_path), "ok": False, "error": f"bad plan: {exc}"}
    first = (plan_obj.get("request_template") or "").split("\n", 1)[0]
    method = first.split(" ")[0].upper() if first else "GET"
    if method not in ("GET", "HEAD", "OPTIONS") and not spec.get("allowWrite") and not spec.get("dryRun"):
        return {"plan": str(plan_path), "ok": False, "skipped": True,
                "error": "write method requires allowWrite=true"}
    if plan_obj.get("kind") == "race":
        return {"plan": str(plan_path), "ok": False, "skipped": True,
                "error": "race runner is not installed yet; use single/chain/idor plans"}
    cmd = [sys.executable, str(ENGINE), "--plan", str(plan_path), "--out", str(out_dir)]
    if spec.get("dryRun"):
        cmd.append("--dry-run")
    # 代理：spec 优先，其次 plan 里已有的 proxy；都没有才看环境（死端口哨兵已排除）
    proxy = str(spec.get("proxy") or "").strip() or str(plan_obj.get("proxy") or "").strip() \
        or (resolve_proxy(spec) or "")
    if proxy:
        cmd += ["--proxy", proxy]
    # 超时按限速算：单计划要发 (载荷数 + 基线重复) 次请求，不能拍脑袋给 600s
    try:
        rate = max(1, int(plan_obj.get("rate_limit_per_min") or 12))
    except Exception:  # noqa: BLE001
        rate = 12
    n_payload = len(plan_obj.get("payloads") or []) or 1
    budget = 60 + int(n_payload / rate * 60) + 90
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True,
                       encoding="utf-8", errors="replace",
                       env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=budget)
    diffs = out_dir / "diffs.csv"
    rows = []
    if diffs.exists():
        with io.open(diffs, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                if r.get("verdict") in ("BASELINE",):
                    continue
                rows.append({k: r.get(k, "") for k in
                             ("label", "payload", "status", "len", "net_len", "delta_ms", "markers",
                              "semantic", "semantic_changes", "verdict", "reason")})
    verify_out = None
    if plan_obj.get("verify") and not spec.get("dryRun"):
        verify_script = FUZZ / "fuzz_verify.py"
        if verify_script.exists():
            vcmd = [sys.executable, str(verify_script), "--plan", str(plan_path), "--run", str(out_dir)]
            if spec.get("allowWrite"):
                vcmd.append("--allow-write")
            vp = subprocess.run(vcmd, cwd=str(ROOT), capture_output=True, text=True,
                                encoding="utf-8", errors="replace",
                                env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=300)
            try:
                verify_out = json.loads(vp.stdout.strip().splitlines()[-1])
            except Exception:
                verify_out = {"ok": False, "stderr": vp.stderr[-1000:]}
    return {"plan": str(plan_path), "ok": p.returncode == 0, "out": str(out_dir),
            "requests": len(rows), "verify": verify_out,
            "stdout": (p.stdout or "").strip().splitlines()[-3:],
            "stderr": (p.stderr or "").strip().splitlines()[-3:], "rows": rows[:12]}


def run(spec: dict) -> dict:
    target = spec.get("target") or "adhoc"
    base = (EVIDENCE / target / "evidence" / "fuzz") if spec.get("target") else (RUNS)
    base.mkdir(parents=True, exist_ok=True)
    # 单次调用跑多少份计划：默认 2（DSH bundle 有执行时限，跑多了会被掐成 exit -1）
    max_plans = int(spec.get("limit") or spec.get("maxPlans") or 2)
    max_plans = max(1, min(max_plans, 20))
    paths: list[Path] = []
    all_plans: list[Path] = []
    if spec.get("planPath"):
        p = Path(spec["planPath"])
        if not p.is_absolute():
            p = ROOT / p
        if p.is_dir():
            all_plans = sorted(p.glob("*.json"))
            paths = all_plans[:max_plans]
        else:
            paths = [p]
    elif spec.get("planDir"):
        p = Path(spec["planDir"])
        if not p.is_absolute():
            p = ROOT / p
        all_plans = sorted(p.glob("*.json"))
        paths = all_plans[:max_plans]
    if not paths:
        return {"ok": False, "error": "planPath or planDir is required"}
    results = []
    for p in paths:
        out_dir = base / f"{now_tag()}-{p.stem}"
        if out_dir.exists():
            out_dir = base / unique_path(base, out_dir.name).name
        results.append(run_plan(p, spec, out_dir))
    skipped = [q.name for q in all_plans[max_plans:]]
    return {"ok": all(r.get("ok") for r in results),
            "summary": f"run {len(results)} plan(s)"
                       + (f"，另有 {len(skipped)} 份未跑（加 limit 继续）" if skipped else ""),
            "data": {"runs": results, "skippedPlans": skipped}}


def classify_row(row: dict) -> str:
    status = str(row.get("status", ""))
    markers = str(row.get("markers", "")).lower()
    verdict = str(row.get("verdict", ""))
    reason = str(row.get("reason", ""))
    semantic = str(row.get("semantic", "")).strip().upper()
    # 基线自身不可达：结论是无效，不是无差分；这是 diffprobe 的既有纪律。
    if "无效" in verdict or "基线不可达" in reason:
        return "INVALID"
    # 命中防护优先于差分，除非引擎已把该行明确标成差分（防护页差异仍可能值钱）。
    if "命中防护" in verdict:
        return "BLOCKED"
    if status in ("403", "429", "503") and "差分" not in verdict:
        return "BLOCKED"
    if "差分" in verdict or semantic == "DIFF":
        return "DIFFERENTIAL"
    return "NO_SIGNAL"


def diff_risk(row: dict) -> str:
    """Classify a differential by what actually changed, so an error-code branch
    is not mistaken for an authorization/state change."""
    changes = str(row.get("semantic_changes", "")).lower()
    if any(k in changes for k in ("ownerid", "userid", "role", "status", "amount", "phone", "data.")):
        return "state-or-data"
    if any(k in changes for k in ("errorcode", "errormsg", "error_code", "message")):
        return "error-channel"
    return "transport"


def verdict(spec: dict) -> dict:
    run_path = spec.get("runPath")
    if not run_path:
        return {"ok": False, "error": "runPath is required"}
    p = Path(run_path)
    if not p.is_dir():
        return {"ok": False, "error": f"not a run directory: {p}"}
    counts: dict[str, int] = {}
    risks: dict[str, int] = {}
    findings = []
    diffs = p / "diffs.csv"
    if diffs.exists():
        with io.open(diffs, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                cls = classify_row(r)
                counts[cls] = counts.get(cls, 0) + 1
                if cls in ("DIFFERENTIAL", "BLOCKED"):
                    risk = diff_risk(r) if cls == "DIFFERENTIAL" else "blocked"
                    risks[risk] = risks.get(risk, 0) + 1
                    findings.append({"class": cls, "risk": risk, "label": r.get("label", ""),
                                     "status": r.get("status", ""), "net_len": r.get("net_len", ""),
                                     "semantic": r.get("semantic", ""),
                                     "semantic_changes": r.get("semantic_changes", ""),
                                     "verdict": r.get("verdict", ""), "reason": r.get("reason", "")})
    state = p / "state.csv"
    if state.exists():
        with io.open(state, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                if str(r.get("changed", "")).lower() in ("1", "true", "yes"):
                    counts["STATE_CHANGED"] = counts.get("STATE_CHANGED", 0) + 1
                    findings.append({"class": "STATE_CHANGED", "label": r.get("label", ""),
                                     "path": r.get("path", ""), "value": r.get("value", "")})
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no diffs.csv/state.csv"
    if risks:
        summary += " | " + ", ".join(f"{k}={v}" for k, v in sorted(risks.items()))
    return {"ok": True, "summary": summary,
            "data": {"runPath": str(p), "counts": counts, "risks": risks, "findings": findings[:15]}}


# ---------------------------------------------------------------- doctor / bizmap

def doctor() -> dict:
    checks = []
    def check(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    check("python", sys.version_info >= (3, 9), sys.version.split()[0])
    check("engine", ENGINE.exists(), str(ENGINE))
    check("fuzz_dir", FUZZ.exists(), str(FUZZ))
    check("verify_runner", (FUZZ / "fuzz_verify.py").exists(), str(FUZZ / "fuzz_verify.py"))
    check("payloadsets", PAYLOADS.exists(), str(PAYLOADS))
    for name in ("logic_role", "logic_tenant", "logic_amount", "logic_massassign", "fuzz_params"):
        check("set:" + name, (PAYLOADS / f"{name}.json").exists())
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def bizmap(spec: dict) -> dict:
    target = spec.get("target")
    if not target:
        return {"ok": False, "error": "target is required"}
    p = EVIDENCE / target / "fuzz-bizmap.json"
    if spec.get("data"):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(spec["data"], ensure_ascii=False, indent=2), encoding="utf-8")
        return {"ok": True, "summary": f"bizmap written: {p}", "data": {"path": str(p)}}
    if not p.exists():
        return {"ok": False, "error": f"bizmap not found: {p}"}
    return {"ok": True, "summary": f"bizmap: {p}", "data": json.loads(p.read_text(encoding="utf-8"))}


# ---------------------------------------------------------------- main

def dispatch(spec: dict) -> dict:
    action = spec.get("action")
    if action == "harvest":
        return harvest(spec)
    if action == "plan":
        return plan(spec)
    if action == "run":
        return run(spec)
    if action == "verdict":
        return verdict(spec)
    if action == "doctor":
        return doctor()
    if action == "bizmap":
        return bizmap(spec)
    return {"ok": False, "error": f"unknown action: {action}"}


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    import argparse
    p = argparse.ArgumentParser(description="fuzz/logic planner over diffprobe")
    p.add_argument("--spec")
    p.add_argument("action", nargs="?")
    p.add_argument("--response")
    p.add_argument("--request")
    p.add_argument("--target")
    p.add_argument("--kind")
    p.add_argument("--seeds")
    p.add_argument("--params", nargs="*")
    p.add_argument("--proxy", help="出站代理，如 http://127.0.0.1:7897；写进 plan 并透传给引擎")
    p.add_argument("--rate", type=int, help="每分钟请求上限（写入 plan）")
    p.add_argument("--limit", type=int, help="候选计划条数上限")
    p.add_argument("--scheme", help="http / https")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    if args.spec:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8-sig"))
        for k, v in (("proxy", args.proxy), ("rate", args.rate), ("limit", args.limit), ("scheme", args.scheme)):
            if v not in (None, "") and k not in spec:
                spec[k] = v
    else:
        spec = {"action": args.action, "response": args.response, "request": args.request,
                "target": args.target, "kind": args.kind, "seeds": args.seeds, "params": args.params,
                "proxy": args.proxy, "rate": args.rate, "limit": args.limit, "scheme": args.scheme}
    try:
        res = dispatch(spec)
    except Exception as exc:
        res = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    out(res)
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
