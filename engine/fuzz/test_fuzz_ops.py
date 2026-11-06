#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""fuzz_ops 回归自检（离线，不发任何网络请求）。

覆盖 2026-11-06 实测暴露的三个缺陷：
  1. 计划文件名只精确到秒 → 同秒并发调用互相覆盖（实测三次 plan 只剩一份）；
  2. 生成的计划没有 proxy 通道 → 无法经用户代理出口发包；
  3. sqli 计划只打 params[0]，且载荷集里已有的成对真假载荷没人用 → 真假不可判。

跑法：python 作战工具\fuzz\test_fuzz_ops.py
退出码 0 = 全过。
"""
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fuzz_ops  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    if cond:
        print("  [OK] %s" % name)
    else:
        print("  [FAIL] %s %s" % (name, detail))
        FAILED.append(name)


RAW = ("GET /api/search?keywords=test&page=1 HTTP/1.1\n"
       "Host: 47.93.21.26\n"
       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\n"
       "Connection: close\n")


def main():
    tmp_target = "_selftest-fuzz-ops"
    tmp_dir = fuzz_ops.PLANS / tmp_target
    root_tmp = fuzz_ops.FUZZ / "_selftest_tmp"
    shutil.rmtree(tmp_dir, ignore_errors=True)
    shutil.rmtree(root_tmp, ignore_errors=True)
    root_tmp.mkdir(parents=True, exist_ok=True)
    try:
        # 1) 同秒多次 plan 不再互相覆盖
        paths = []
        for i in range(3):
            res = fuzz_ops.plan({"action": "plan", "kind": "sqli", "target": tmp_target,
                                 "request": RAW, "params": ["keywords", "page"], "limit": 8})
            check("plan#%d 成功" % i, res.get("ok"), str(res.get("error")))
            paths.extend(p["path"] for p in res.get("data", {}).get("plans", []))
        check("三次 plan 产出的文件互不相同", len(set(paths)) == len(paths),
              "%d 个路径 / %d 个不同" % (len(paths), len(set(paths))))
        check("产出的计划文件都真实存在", all(Path(p).exists() for p in paths))

        # 2) 每个参数各出一份计划（不再只打 params[0]）
        params_hit = set()
        for p in paths:
            plan_obj = json.loads(Path(p).read_text(encoding="utf-8"))
            cand = (plan_obj.get("meta") or {}).get("candidate") or {}
            params_hit.add(cand.get("param"))
        check("覆盖全部指定参数", {"keywords", "page"} <= params_hit, str(params_hit))

        # 3) 成对真假载荷 + 单端点请求上限
        labels = []
        for p in paths:
            plan_obj = json.loads(Path(p).read_text(encoding="utf-8"))
            labels.append([x["label"] for x in plan_obj.get("payloads", [])])
        check("每份计划都带真假成对标签",
              all("true-1" in l and "false-1" in l and "baseline" in l and "control" in l for l in labels),
              str(labels[:1]))
        check("单端点请求数 ≤10", all(len(l) <= 10 for l in labels),
              str([len(l) for l in labels]))

        # 4) proxy 通道：spec 显式指定
        res = fuzz_ops.plan({"action": "plan", "kind": "sqli", "target": tmp_target,
                             "request": RAW, "params": ["keywords"], "limit": 2,
                             "proxy": "http://127.0.0.1:7897"})
        p0 = res["data"]["plans"][0]["path"]
        plan_obj = json.loads(Path(p0).read_text(encoding="utf-8"))
        check("proxy 写进计划", plan_obj.get("proxy") == "http://127.0.0.1:7897",
              str(plan_obj.get("proxy")))

        # 5) proxy 通道：环境变量 FUZZ_PROXY
        old = fuzz_ops.os.environ.get("FUZZ_PROXY")
        fuzz_ops.os.environ["FUZZ_PROXY"] = "http://127.0.0.1:9999"
        try:
            res = fuzz_ops.plan({"action": "plan", "kind": "sqli", "target": tmp_target,
                                 "request": RAW, "params": ["keywords"], "limit": 2})
            p1 = res["data"]["plans"][0]["path"]
            plan_obj = json.loads(Path(p1).read_text(encoding="utf-8"))
            check("FUZZ_PROXY 被采纳", plan_obj.get("proxy") == "http://127.0.0.1:9999",
                  str(plan_obj.get("proxy")))
        finally:
            if old is None:
                fuzz_ops.os.environ.pop("FUZZ_PROXY", None)
            else:
                fuzz_ops.os.environ["FUZZ_PROXY"] = old

        # 6) 死端口哨兵不得被当成真代理
        for var in ("HTTPS_PROXY", "HTTP_PROXY"):
            fuzz_ops.os.environ[var] = "http://127.0.0.1:9"
        try:
            missing = Path(root_tmp) / "no-such-proxy.json"
            check("跳过 127.0.0.1:9 哨兵", fuzz_ops.resolve_proxy({}, config_path=missing) is None,
                  str(fuzz_ops.resolve_proxy({}, config_path=missing)))
        finally:
            for var in ("HTTPS_PROXY", "HTTP_PROXY"):
                fuzz_ops.os.environ.pop(var, None)

        # 6b) 工作区默认代理文件生效（bundle 的 fuzz 工具没有 proxy 入参，只能走这条）
        cfg = Path(root_tmp) / "proxy.json"
        cfg.write_text(json.dumps({"proxy": "http://127.0.0.1:7897"}), encoding="utf-8")
        check("工作区默认代理文件被采纳",
              fuzz_ops.resolve_proxy({}, config_path=cfg) == "http://127.0.0.1:7897",
              str(fuzz_ops.resolve_proxy({}, config_path=cfg)))

        # 7) 计划名唯一性不依赖时间精度（连续两次 now_tag 不同）
        tags = {fuzz_ops.now_tag() for _ in range(50)}
        check("now_tag 连续取值不重复", len(tags) == 50, "%d/50" % len(tags))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        shutil.rmtree(root_tmp, ignore_errors=True)

    print("")
    if FAILED:
        print("未通过：%s" % "、".join(FAILED))
        return 1
    print("fuzz_ops 回归自检全过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
