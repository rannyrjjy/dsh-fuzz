# -*- coding: utf-8 -*-
"""
差分探针的离线自检服务（只监听 127.0.0.1）。零对外请求。

路由与故意植入的可预测行为：

  GET /probe?p=…            传输层自检（原有行为，向后兼容）
      含 SLEEP    → 延迟 2s（时间盲注通道）
      含 QUOTE    → 返回 WAF 拦截页（防护层）
      含 BOOLTRUE → 不同长度（布尔通道）

  GET /json?p=…             JSON 语义自检
      恒返回 {"code":200,"ts":<动态>,"data":{"userId":…,"roles":[…],"name":…}}
      含 TEACHER  → roles[0]=teacher（与 student **等长**，传输层四维完全一致）
      含 OTHER    → data.userId 变成 10002（他人对象）
      含 NOTARGET → 走 SPA 回落：返回入口 HTML（触达断言应失败）
      含 SOFT404  → 返回自定义软 404 页但状态码 200

  GET /obj/<id>             多身份矩阵自检
      X-User 与对象 owner 一致 → 200 {"ok":true,…}
      否则                     → 403 {"ok":false}
      owner 映射：10001→user_a，10002→user_b

  POST /seq/<step>          状态机自检（init → verify → commit）
      正常顺序 init→verify→commit → 200 {"stage":"done"}
      跳步（无前序 verify）        → 200 {"stage":"skipped"}  ← 故意留下的流程跳跃
      重放 commit                  → 200 {"stage":"replayed"}
"""
import http.server
import json
import socketserver
import time
import urllib.parse

ENTRY_HTML = ("<!doctype html><html><head><title>入口页</title></head>"
              "<body><div id=app></div></body></html>")
SOFT404 = ("<html><body><h1>抱歉，页面不存在</h1><p>请返回首页</p></body></html>")


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body, ctype="text/html;charset=UTF-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -------------------------------------------------- /probe（原有传输层自检）
    def _probe(self, params):
        p = (params.get("p") or [""])[0]
        if "SLEEP" in p or "WAITFOR" in p:
            time.sleep(2.0)
        if "QUOTE" in p:
            return self._send(200, "<html><div class='promptTwo'>抱歉</div>"
                                   "<p>输入参数含有不允许的串，可能引起注入或跨站脚本风险，"
                                   "禁止本页面执行！</p></html>")
        body = ("HIT:" + p + "|campusName=测试大学|errorCode=0") if "BOOLTRUE" in p else ("MISS:" + p)
        return self._send(200, body)

    # -------------------------------------------------- /json（语义层自检）
    def _json(self, params):
        p = (params.get("p") or [""])[0]
        if "NOTARGET" in p:
            return self._send(200, ENTRY_HTML)
        if "SOFT404" in p:
            return self._send(200, SOFT404)
        uid = 10002 if "OTHER" in p else 10001
        role = "teacher" if "TEACHER" in p else "student"
        payload = {
            "code": 200,
            "ts": int(time.time() * 1000),          # 动态字段：必须靠 ignore_paths 忽略
            "traceId": "t-%05d" % (int(time.time() * 1000) % 100000),  # 定宽，避免长度抖动
            "data": {"userId": uid, "roles": [role], "name": "测试用户", "owner": "user_a" if uid == 10001 else "user_b"},
        }
        return self._send(200, json.dumps(payload, ensure_ascii=False), "application/json")

    # -------------------------------------------------- /obj/<id>（矩阵自检）
    def _obj(self, path):
        oid = path.rsplit("/", 1)[-1]
        owner = {"10001": "user_a", "10002": "user_b"}.get(oid)
        user = (self.headers.get("X-User") or "").strip()
        if owner and user == owner:
            return self._send(200, json.dumps({"ok": True, "id": oid, "owner": owner,
                                               "name": "对象" + oid}), "application/json")
        if owner:
            return self._send(403, json.dumps({"ok": False, "error": "forbidden"}), "application/json")
        return self._send(404, json.dumps({"ok": False, "error": "not found"}), "application/json")

    # -------------------------------------------------- /seq/<step>（状态机自检）
    SEQ = {}

    def _seq(self, path, params):
        step = path.rsplit("/", 1)[-1]
        sid = (params.get("sid") or ["anon"])[0]
        state = self.SEQ.setdefault(sid, {"verified": False, "done": False, "commits": 0})
        if step == "init":
            state["verified"] = False
            state["done"] = False
            state["commits"] = 0
            return self._send(200, json.dumps({"stage": "init"}), "application/json")
        if step == "verify":
            state["verified"] = True
            return self._send(200, json.dumps({"stage": "verified"}), "application/json")
        if step == "commit":
            state["commits"] += 1
            if state["commits"] > 1:
                return self._send(200, json.dumps({"stage": "replayed"}), "application/json")
            if not state["verified"]:
                return self._send(200, json.dumps({"stage": "skipped"}), "application/json")
            return self._send(200, json.dumps({"stage": "done"}), "application/json")
        return self._send(404, json.dumps({"stage": "unknown"}), "application/json")

    def _dispatch(self):
        sp = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(sp.query)
        if sp.path == "/probe":
            return self._probe(params)
        if sp.path == "/json":
            return self._json(params)
        if sp.path.startswith("/obj/"):
            return self._obj(sp.path)
        if sp.path.startswith("/seq/"):
            return self._seq(sp.path, params)
        return self._send(200, ENTRY_HTML)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._dispatch()

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    with S(("127.0.0.1", port), H) as httpd:
        sys.stderr.write("selftest server on http://127.0.0.1:%d\n" % port)
        httpd.serve_forever()
