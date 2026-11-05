# engine/

两层结构，职责不重叠：

```text
engine/
├─ fuzz/          计划器 / 执行编排 / 判定（fuzz_ops.py）
│                状态回读（fuzz_verify.py）
│                判定回归（bench_verdict.py）
├─ diffprobe/     唯一的请求执行引擎：限速、破坏性载荷闸门、
│                传输四维比对、语义比对（dp_semantic.py）、一行式入口（quick.py）
└─ payloadsets/   共享载荷集，diffprobe 与 fuzz 都从这里取
```

## 数据流

```text
harvest  → seeds.json
plan     → plans/<target>/*.json   （基线 + 对照 + payload，可带 verify）
run      → diffprobe → runs/<tag>/diffs.csv
         → fuzz_verify（若计划带 verify）→ runs/<tag>/state.csv
verdict  → 分类计数（DIFFERENTIAL/BLOCKED/INVALID/STATE_CHANGED/NO_SIGNAL）
```

## 路径约定

- `diffprobe.py` 从 `HERE.parent/payloadsets` 读载荷，因此 `diffprobe/` 与 `payloadsets/` 必须同级。
- `fuzz_ops.py` 从 `HERE.parent` 找 `diffprobe/`，工作区、证据目录、运行时状态由
  `DSH_FUZZ_WORKSPACE` / `DSH_FUZZ_EVIDENCE_DIR` / `DSH_FUZZ_STATE` 决定（见根 README）。
- 运行时状态（`plans/`、`seeds/`、`runs/`）默认落在 `<workspace>/.dsh-fuzz/`，不写进插件目录。

## 独立的 diffprobe 用法

不经过插件也能用，适合脚本化：

```sh
python engine/diffprobe/quick.py --url "https://example.com/api/item/9?a=1" --inject a --set sqli:boolean --dry-run
python engine/diffprobe/diffprobe.py --plan plan.json --out runs/20260101-demo
python engine/diffprobe/selftest_server.py     # 本地假目标，验证判定逻辑
```

`selftest_server.py` 只监听 `127.0.0.1`，不产生外网请求；`/probe` 与 `/json` 的故意行为可以用来确认
「延迟 / 长度 / 语义 / 防护页」四类信号是否按预期分类。