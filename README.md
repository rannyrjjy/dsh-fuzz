# dsh-fuzz

> Differential fuzz / logic-test planner for **DeepSeek Harness (DSH)**, built on the `diffprobe` packet engine.
> 基于 diffprobe 的差分 fuzz / 逻辑测试插件：**抽值 → 计划 → 执行 → 判定**。

插件只注册一个 DSH Host 工具 `fuzz`，负责参数映射与子进程编排；**所有请求始终由 `engine/diffprobe` 执行**，没有第二个请求引擎。计划、种子、原始请求/响应都落盘，不进对话。

> 仅用于**已授权**的渗透测试、CTF/靶场和自有系统评估。默认只读，写方法需要显式 `allowWrite: true`。

## 它解决什么

手工测越权/逻辑漏洞时，最贵的是「构造对照请求 + 判定响应差异」这两步，而不是发一个包。
这个插件把这两步自动化，并且坚持三条纪律：

1. **基线可比**：每条 payload 都带 baseline 与同类型对照，避免「长度不同就是洞」。
2. **差异不等于漏洞**：判定区分传输层差异、错误分支（`errorCode/errorMsg`）和真正值得回读的状态/数据变化（`ownerId/role/status/amount/...`）。
3. **可复核**：`run` 产出 `diffs.csv`，`verify` 产出 `state.csv`，`verdict` 只做分类，证据留在工作区。

## 环境要求

- Node.js 22.19+（或 24+）
- Python 3.9+，`python` / `python3` 在 PATH 中
- DeepSeek Harness（支持 bundle 插件 / Host 工具）

## 安装

插件是纯 JS + Python，无构建步骤。任选一种：

```sh
# --profile 是必填项：把 <profile> 换成你的 profile 名（桌面版通常为 desktop）
# 1) 从 GitHub 安装（公开仓库）
dsh plugin --profile <profile> add github:rannyrjjy/dsh-fuzz

# 2) 本地安装（git clone / 解压后，把 <plugin-dir> 换成绝对路径）
dsh plugin --profile <profile> add file:<plugin-dir>
```

> 本地路径写法随平台：Windows 用 `file:D:\tools\dsh-fuzz`，macOS/Linux 用 `file:/opt/dsh-fuzz`。
> 安装后重启 DeepSeek Harness（或让插件管理器重载 profile），工具列表会出现 `fuzz`。

## 配置

默认值在 `index.js` 里解析，**不配置也能用**。需要覆盖时，在你的 DSH patch 层加一段 `dsh-fuzz`：

```yaml
- insert:
    - id: dsh-fuzz
      name: dsh-fuzz
      config:
        workspaceDir: /path/to/workspace   # 建议显式配置：证据、@file、diffprobe cwd 的根
        pythonPath: python3                # Windows 上默认 python
        evidenceRoot: evidence             # 证据目录名，默认「漏洞记录」
        timeoutMs: 300000
```

Windows 路径写 `C:/work/pentest` 或 `C:\\work\\pentest` 均可。

| 键 | 默认 | 说明 |
|---|---|---|
| `workspaceDir` | DSH Host 当前目录（或 `DSH_FUZZ_WORKSPACE`） | 工作区根；`@file` 相对路径、diffprobe 的 cwd、证据目录都基于它 |
| `pythonPath` | `python`（Windows）/ `python3` | Python 解释器 |
| `enginePath` | `<插件目录>/engine/fuzz/fuzz_ops.py` | 引擎入口，可指向另一份引擎 |
| `evidenceRoot` | `漏洞记录` | 证据目录名，位于 `workspaceDir` 下，可改成任意名字 |
| `timeoutMs` | `300000` | 单次子进程超时（毫秒） |

引擎也接受环境变量（插件会自动注入前三个）：

| 变量 | 作用 |
|---|---|
| `DSH_FUZZ_WORKSPACE` | 同 `workspaceDir` |
| `DSH_FUZZ_EVIDENCE_DIR` | 同 `evidenceRoot` |
| `DSH_FUZZ_STATE` | `plans/seeds/runs` 的落盘位置，默认 `<workspace>/.dsh-fuzz` |
| `DSH_FUZZ_ENGINE` | 含 `diffprobe/` 与 `payloadsets/` 的引擎根 |

## `fuzz` 工具

| action | 做什么 | 是否发包 |
|---|---|---|
| `harvest` | 从回包抽带类型的值（id/uuid/phone/token/email/金额…）与字段名，生成 `seeds.json` | 否 |
| `plan` | 生成 diffprobe 计划（见下表 kind），带 baseline + 同类型对照，可选 `verify` | 否（`dryRun` 仅校验） |
| `run` | 调 diffprobe 执行计划，限速、命中 403/429/503 即停；写方法需 `allowWrite` | 是 |
| `verdict` | 读 `diffs.csv`/`state.csv` 分类：`DIFFERENTIAL` / `BLOCKED` / `INVALID` / `STATE_CHANGED` / `NO_SIGNAL` | 否 |
| `doctor` | 检查 Python、引擎、payloadsets 是否齐备 | 否 |
| `bizmap` | 读写 `<workspace>/<evidenceRoot>/<target>/fuzz-bizmap.json` 目标业务地图 | 否 |

### plan kind

| kind | 用途 |
|---|---|
| `chain` | 把别的接口返回值移植到目标参数位（BOLA/引用链） |
| `idor` | 邻号/对照/他人 ID，配 `verify` 回读 owner 字段 |
| `massassign` | JSON body 追加 `role/isAdmin/tenantId/...`，回读是否持久化 |
| `role` / `tenant` / `amount` | 角色、租户、金额字段候选 |
| `param` | 追加隐藏参数名 |
| `bypass` | 路径段归一化绕过（`%61dmin`、`admin/`、`admin/..;/`、`..%2f`…） |
| `sqli` `xss` `ssrf` `lfi` `ssti` `cmdi` `xxe` | 复用 `engine/payloadsets/` 的经典类载荷 |

## 判定口径

| 类别 | 含义 |
|---|---|
| `DIFFERENTIAL` | 引擎判差分，或语义层判 `DIFF` |
| `INVALID` | 基线自身不可达——结论是无效，不是「无差分」 |
| `BLOCKED` | 命中防护（403/429/503 等） |
| `STATE_CHANGED` | `verify` 回读的 JSON path 真的变了 |
| `NO_SIGNAL` | 其余 |

差分再按「变了什么」分级：`state-or-data`（`ownerId/userId/role/status/amount/...`）值得扩大样本；
`error-channel`（只变 `errorCode/errorMsg`）只是错误分支或防护层，**不要当洞**。

## 快速开始（本地开发，离线）

在仓库根目录执行：

```sh
# 1) 环境自检
python engine/fuzz/fuzz_ops.py --spec examples/doctor.json

# 2) 从示例回包抽值（不联网）
python engine/fuzz/fuzz_ops.py --spec examples/harvest.json

# 3) 生成 idor 计划并 dry-run（不联网、不发包）
python engine/fuzz/fuzz_ops.py --spec examples/plan-idor.json
```

引擎离线自检服务（只监听 `127.0.0.1`，用来验证差分判定逻辑本身，不产生外网请求）：

```sh
python engine/diffprobe/selftest_server.py
```

## 目录结构

```text
dsh-fuzz/
├─ index.js                  # DSH 插件：注册 fuzz 工具，转发到引擎
├─ cordis.patch.yml          # bundle patch（一行 insert）
├─ engine/
│  ├─ fuzz/                  # fuzz_ops.py（计划/执行/判定）、fuzz_verify.py（状态回读）、bench_verdict.py（判定回归）
│  ├─ diffprobe/             # 请求执行引擎：限速、破坏性载荷闸门、差分与语义比对
│  └─ payloadsets/           # 共享载荷集（sqli/xss/idor/logic_*/fuzz_params…）
├─ examples/                 # 不含真实目标的示例 spec
└─ locale/                   # 插件标题与描述
```

## 安全边界

- 默认只读：`POST/PUT/PATCH/DELETE` 必须 `allowWrite: true`。
- 破坏性载荷拒绝、限速、命中防护即停，全部由 diffprobe 执行，计划层不能绕过。
- 原始请求/响应只落 `<workspace>/<evidenceRoot>/<target>/evidence/fuzz/` 或 `<workspace>/.dsh-fuzz/runs/`。
- `race` 并发与 `state` 状态机生成尚未实现（schema 已留位），当前 `run` 会跳过 `kind=race` 计划。
- `verify` 是「一批跑完再回读」，对单值计划有效；连续写 payload 是累计状态，需要逐 payload 隔离时请拆计划。
- 靶标鉴权材料（Cookie/Token）只出现在你传入的原始请求里，插件不做持久化；示例文件使用 `REDACTED`。

## 更新

```sh
dsh plugin --profile <profile> update dsh-fuzz
# 或 remove 后重新 add
dsh plugin --profile <profile> remove dsh-fuzz
dsh plugin --profile <profile> add github:rannyrjjy/dsh-fuzz
```

## License

MIT，见 [LICENSE](LICENSE)。
