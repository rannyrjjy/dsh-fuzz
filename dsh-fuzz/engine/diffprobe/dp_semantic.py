#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""diffprobe 语义层 —— 补上"状态码/长度/耗时/标记"四维看不见的那一半。

为什么需要（历史复盘）：响应长度完全相同、状态码完全相同，
但 /data/userId 从 10001 变成 10002、/data/roles/0 从 student 变成 admin ——
四维差分全 SAME，越权却真实存在。仅靠传输层四个数字，这类问题永远抓不到。

本模块提供四件事：
  1. JSON 结构差分：忽略动态字段、指定观察路径、输出具体变化路径与变化类型
  2. 触达断言：基线不满足时结论是「无效（未证明进入目标业务路径）」，不是「无差分」
  3. 多身份权限矩阵：anonymous / user_a / user_b / admin × object_a / object_b
  4. 状态机差分：正常顺序 / 跳步 / 重放 / 跨会话

它只被 diffprobe.py 调用，沿用同一个限速器与落盘格式；不单独发包。
"""

import io
import json
import re

MAX_SCALAR_REPR = 160


# ---------------------------------------------------------------- JSON 结构差分

def _type_name(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _scalar_repr(v):
    if isinstance(v, str):
        return v if len(v) <= MAX_SCALAR_REPR else v[:MAX_SCALAR_REPR] + "…"
    return json.dumps(v, ensure_ascii=False)


def walk_json(obj, prefix="", out=None):
    r"""把 JSON 摊平成 {JSON Pointer: {"type":..,"value":..,"size":..}}。

    容器节点也入表（size=子元素个数），这样"数组数量变化"能被单独识别出来，
    而不是混在某个标量的值变化里。
    """
    if out is None:
        out = {}
    t = _type_name(obj)
    node = {"type": t}
    if t in ("object", "array"):
        node["size"] = len(obj)
        out[prefix or "/"] = node
        items = obj.items() if t == "object" else enumerate(obj)
        for k, v in items:
            key = str(k).replace("~", "~0").replace("/", "~1")
            walk_json(v, "%s/%s" % (prefix, key), out)
    else:
        node["value"] = _scalar_repr(obj)
        out[prefix or "/"] = node
    return out


def _matches(path, patterns):
    for p in patterns or []:
        if not p:
            continue
        if p.startswith("re:"):
            if re.search(p[3:], path):
                return True
            continue
        if path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


def structural_diff(a, b, ignore_paths=(), watch_paths=()):
    r"""返回变化列表。

    change ∈ {added, removed, type_changed, value_changed, size_changed}
    只关注 watch_paths（若非空）下的路径；ignore_paths 优先于 watch_paths。
    """
    wa, wb = walk_json(a), walk_json(b)
    changes = []
    for path in sorted(set(wa) | set(wb)):
        if _matches(path, ignore_paths):
            continue
        if watch_paths and not _matches(path, watch_paths) and path != "/":
            continue
        na, nb = wa.get(path), wb.get(path)
        if na is None:
            changes.append({"path": path, "change": "added", "after": nb})
            continue
        if nb is None:
            changes.append({"path": path, "change": "removed", "before": na})
            continue
        if na["type"] != nb["type"]:
            changes.append({"path": path, "change": "type_changed",
                            "before": na["type"], "after": nb["type"]})
            continue
        if na["type"] in ("object", "array"):
            if na.get("size") != nb.get("size"):
                changes.append({"path": path, "change": "size_changed",
                                "before": na.get("size"), "after": nb.get("size")})
            continue
        if na.get("value") != nb.get("value"):
            changes.append({"path": path, "change": "value_changed",
                            "before": na.get("value"), "after": nb.get("value")})
    return changes


def try_parse_json(body_bytes, headers=None):
    """解析 JSON；返回 (obj 或 None, 失败原因)。非 JSON 响应是正常情况，不是错误。"""
    try:
        text = body_bytes.decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        return None, "无法按 UTF-8 解码：%s" % exc
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[":
        ct = ""
        for k, v in (headers or []):
            if k.lower() == "content-type":
                ct = v
        return None, "响应体不是 JSON 起始（Content-Type=%s）" % (ct or "未知")
    try:
        return json.loads(text), ""
    except ValueError as exc:
        return None, "JSON 解析失败：%s" % exc


def json_pointer_get(obj, pointer):
    if not pointer or pointer == "/":
        return obj
    cur = obj
    for raw in pointer.strip("/").split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            if not key.isdigit() or int(key) >= len(cur):
                return None
            cur = cur[int(key)]
        elif isinstance(cur, dict):
            if key not in cur:
                return None
            cur = cur[key]
        else:
            return None
    return cur


def check_reachability(spec, baseline):
    r"""基线触达断言。返回 (是否满足, 不满足原因列表)。

    spec: {"baseline_status": 200, "baseline_json": {"/code": 200},
           "required_markers": ["查询成功"]}
    """
    if not spec:
        return True, []
    problems = []
    if spec.get("baseline_status") is not None and baseline.get("status") != spec["baseline_status"]:
        problems.append("基线状态码 %s ≠ 断言 %s" % (baseline.get("status"), spec["baseline_status"]))
    body = baseline.get("body") or b""
    text = body.decode("utf-8", errors="replace")
    for marker in spec.get("required_markers") or []:
        if marker and marker not in text:
            problems.append("基线正文缺少必需标记 %r" % marker)
    want = spec.get("baseline_json") or {}
    if want:
        obj, why = try_parse_json(body, baseline.get("headers"))
        if obj is None:
            problems.append("触达断言要求 JSON 字段，但%s" % why)
        else:
            for ptr, expected in want.items():
                actual = json_pointer_get(obj, ptr)
                if actual != expected:
                    problems.append("基线 %s = %r ≠ 断言 %r" % (ptr, actual, expected))
    return (not problems), problems


# ---------------------------------------------------------------- 矩阵 / 状态机辅助

ALLOW = "允许"
DENY = "拒绝"
UNKNOWN = "待判"


def classify_cell(status):
    if status is None:
        return UNKNOWN
    if 200 <= status < 300:
        return ALLOW
    if status in (401, 403, 404, 405, 410):
        return DENY
    return UNKNOWN


def render_matrix(rows, cols, cells):
    """cells: {(row_label, col_label): {"status":..,"verdict":..,"flag":..,"evidence":..}}"""
    width = max([len("上下文")] + [len(str(r)) for r in rows])
    head = "%-*s" % (width, "上下文") + "".join(" | %-14s" % c for c in cols)
    lines = [head, "-" * len(head)]
    for r in rows:
        line = "%-*s" % (width, r)
        for c in cols:
            cell = cells.get((r, c), {})
            label = cell.get("verdict", "-")
            if cell.get("flag"):
                label += "!"
            line += " | %-14s" % ("%s(%s)" % (label, cell.get("status", "-")))
        lines.append(line)
    return "\n".join(lines)


def sequence_fingerprint(steps):
    """把一次执行的步骤结果压成指纹，用于跨变体比对。"""
    return "|".join("%s:%s:%s" % (s["label"], s.get("status"), s.get("sha", "-")[:8]) for s in steps)


def extract_var(pattern, text):
    if not pattern:
        return None
    m = re.search(pattern, text or "")
    if not m:
        return None
    return m.group(1) if m.groups() else m.group(0)
