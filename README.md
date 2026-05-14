# AutoPatch-RL

LLM agent 自己改防御策略的小型 demo。**Heuristic-RL 风格**：奖励信号不是更新 NN 权重，而是更新 `policy_intent.yaml` + 编译产物。

```text
state   = 当前 policy_intent + probe 结果 + attack graph + 历史
action  = 改 policy_intent.yaml（每轮一个 control 类别）
reward  = high-risk probe blocked + regression pass + 策略最小
```

## 这个 demo 想证明什么

1. **LLM 能做 RL 闭环**：不训练、不改权重，只靠 in-context state 反馈，agent 也能在多轮里把一个故意搞砸的容器配置一步步收敛回正确状态。
2. **替代专家做配置审计**：iter-0 是一个真实事故级别的错配（SYS_ADMIN cap、unconfined seccomp、host root 挂载、docker.sock 暴露）。agent 应该在 1-2 轮内识别并全部修复。
3. **白盒 probe 是裁判**：LLM 只能改 yaml，不能评分。8 个固定 probe + 红方 LLM 动态 payload 跑真实容器、看真实退出码。所有"防住没"由确定性程序判定，避免 LLM 自评幻觉。
4. **可视化反馈 = RL state**：每轮把"哪条攻击路径活跃 / 已切断 / 新出现"做成攻击图，既给人看（demo 价值），又喂回 agent prompt（学习信号）。

## 架构

```text
target/        漏洞 Flask 应用 + Dockerfile（6 个端点 6 种漏洞）
probes/
  attack_surface/   5 个容器层 probe（mounts/caps/seccomp/userns/kallsyms）
  red_team/         6 个应用层 probe（cmd inj / SSRF / 路径穿越 / SQLi / SSTI / 反序列化）
  regression/       3 个回归 probe（必须保持绿）
schemas/       policy_intent / probe_result 的 JSON schema
policies/
  baseline/    故意错配的初始 policy_intent.yaml
  generated/   每轮编译出的 docker_run.sh + waf_rules.json
core/
  orchestrator.py        单边 demo 主循环（蓝方自我修复）
  adversarial.py         红蓝对抗主循环
  attack_graph.py        从 probe 结果抽 endpoint × technique 二分图
  attack_graph_html.py   渲染独立 HTML（自包含 SVG，离线可看）
  policy_compiler.py     policy_intent.yaml → docker run 命令
  probe_runner.py        跑白名单 probe
  red_probe_runner.py    执行红方 LLM 生成的动态 payload
  judge.py               评分 + 终止条件
  runner.py              容器生命周期
  state_store.py         落盘
agents/
  policy_writer.py       蓝方 LLM agent（生成下一版 policy）
  red_agent.py           红方 LLM agent（生成动态 bypass payload）
  reporter.py            最终 markdown 报告
  prompts/               三个 agent 的 system prompt
reports/runs/  每次跑的全量输出（policy / probe / score / attack_graph / report）
run.ps1        Windows PowerShell 启动器
```

## 6 个漏洞端点

| 端点 | 漏洞 | CWE | 防御杠杆（agent 能改的） |
|---|---|---|---|
| `POST /ping`   | Command Injection | CWE-78  | `app_waf.block_patterns` (regex) |
| `GET /fetch`   | SSRF              | CWE-918 | `ssrf_allowed_schemes` + `ssrf_allowed_hosts` |
| `GET /read`    | Path Traversal    | CWE-22  | `path_traversal_block: true` |
| `GET /search`  | SQL Injection     | CWE-89  | `sqli_parameterized: true` |
| `POST /render` | SSTI              | CWE-1336| `ssti_sandbox: true` |
| `POST /load`   | Insecure Deser.   | CWE-502 | `pickle_disabled: true` 或 `disabled_endpoints: [/load]` |

## Loop 一图流

```text
baseline policy_intent.yaml
   │
   ▼
policy_compiler ── docker_run.sh + waf_rules.json
   │
   ▼
runner up + wait_ready
   │
   ▼
probe_runner ── 8 固定 probe + N 动态 payload → results JSON
   │
   ▼
attack_graph build ── endpoint × technique 二分图（带跨轮 history）
   │
   ▼
judge ── score + is_terminal?
   │
   ├── 终止 → reporter 写 report.md + attack_graph.html
   ▼
policy_writer (LLM) ── 看图 + 看 self-check warnings → 新 policy_intent.yaml → 下一轮
```

---

# 怎么运行（Windows PowerShell）

## 前置依赖

1. **Docker Desktop** — 启动它（任务栏小鲸鱼图标），跑漏洞容器用
2. **Python ≥ 3.9** — 在 PATH 里
3. **Git for Windows** — 提供 Git Bash（probe 脚本 + docker_run.sh 都是 `.sh`，需要真 POSIX bash 而不是 Windows 自带的 WSL launcher）
4. **LLM API Key** — 云雾 API（OpenAI 兼容），或任何 OpenAI 兼容端点

## 配 .env

项目根目录建 `.env`：

```ini
OPENAI_API_KEY=sk-你的key
OPENAI_BASE_URL=https://yunwu.ai/v1
OPENAI_MODEL=claude-haiku-4-5-20251001
# 可选：
# BLUE_MODEL=...      单独覆盖蓝方 model
# RED_MODEL=...       单独覆盖红方 model
MAX_ITERS=12          单边 demo 的最大轮数（默认 6）
```

## 一键启动

```powershell
cd "D:\Codebase\AutoPatch-RL Demo\Qiang-AgentRL-Attack-Defense"

# 第一次跑：自动建 venv、装依赖、构镜像、跑单边 demo
.\run.ps1
```

第一次跑会按顺序自动：
1. 检查 .env / bash / Docker
2. 创建 `.venv` + `pip install -e .`
3. `docker build -t autopatch-target:vuln target/`
4. `python -m core.orchestrator`（蓝方自我修复 N 轮）
5. 写 `report.md` + `attack_graph.html`
6. 清掉容器

如果 PowerShell 报"running scripts is disabled"，先运行一次：

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## 其他命令

```powershell
.\run.ps1 demo      # 单边 demo（默认）
.\run.ps1 battle    # 红蓝对抗 demo（生成 battle.html）
.\run.ps1 graph     # 打开最近一次的 attack_graph.html
.\run.ps1 report    # 打开最近一次的 report.md
.\run.ps1 down      # 只停容器
.\run.ps1 clean     # 清空 reports/runs 和 policies/generated
.\run.ps1 install   # 只装依赖
.\run.ps1 build     # 只构建镜像
```

跑一次 12 轮单边 demo 大概 5-15 分钟（取决于 LLM 延迟，每轮 1 次 policy_writer 调用 + 1 次 red_agent 调用 + 容器重启）。

---

# 怎么解读运行结果

每次跑完 `reports/runs/<时间戳>/` 下面会有：

```
reports/runs/20260514-212027/
├── report.md                    最终报告（agent 写的 markdown）
├── attack_graph.html            交互式攻击图 ★（重点看这个）
├── final/                       最后一轮的产物快照
│   ├── policy_intent.yaml
│   ├── docker_run.sh
│   ├── waf_rules.json
│   ├── probe_results.json
│   ├── score.json
│   └── policy_diff.txt
└── iters/
    ├── iter-000/                第 0 轮 = baseline
    ├── iter-001/
    │   ├── policy_intent.yaml          agent 这一轮改出的策略
    │   ├── docker_run.sh               编译出的 docker 命令
    │   ├── waf_rules.json              编译出的 WAF 规则
    │   ├── probe_results.json          8 个 probe 真实 stdout/exit
    │   ├── red_payloads.json           红方 LLM 这轮生成的动态 payload
    │   ├── red_dynamic_results.json    动态 payload 的执行结果
    │   ├── attack_graph.json           ★ 这一轮的攻击图（json 形式）
    │   ├── score.json                  分数
    │   └── diff.md                     与上一轮的策略 diff
    └── iter-NNN/...
```

## 重点 1：attack_graph.html

`.\run.ps1 graph` 打开。这是最直观的入口。

### 节点

- **左列 6 个端点节点**：
  - 红色填充 = 这一轮被红方打穿了（`compromised`）
  - 绿色填充 = 这一轮守住了（`defended`）
- **右列 N 个 technique 节点**：红方用过的所有攻击手法（"semicolon injection"、"URL-encoded dot-dot"、"decimal IP loopback"、"__class__ chain" 等）

### 边

每条弧线代表"红方用 technique X 攻击 endpoint Y"，颜色编码：

| 边样式 | 含义 |
|---|---|
| **红实线** `bypassed` | 这一轮，X 成功打穿了 Y。防御失败，agent 必须补 |
| **灰虚线** `blocked` | 这一轮，X 被拦下了。防御有效 |
| **绿色描边** `severed` | X 在更早的轮次曾打穿 Y，但**这轮被堵住了**。agent 修复成功的证据 |
| **黄色外发光** `novel` | X 这轮第一次出现（一般是红方动态 payload 的新招） |

### 怎么用

- **拖动顶部滑块从 R0 → RN**，看红→绿的演化（理想情况）
- **看红实线在哪**：agent 还没解决的攻击路径
- **看绿描边的边**：agent 已经修好的路径（成果展示）
- **看黄发光的边**：红方在创新（dynamic payload 新出的招）
- **右侧栏**：每轮的 score、stats、agent 自己的 rationale、edges 完整列表

## 重点 2：score 轨迹

```powershell
$run = (Get-ChildItem reports\runs | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
for ($i=0; $i -le 11; $i++) {
    $f = "$run\iters\iter-{0:000}\score.json" -f $i
    if (Test-Path $f) {
        $j = Get-Content $f -Raw | ConvertFrom-Json
        "iter-{0:000}: total={1}" -f $i, $j.total
    }
}
```

理想轨迹：单调递增（baseline 大负 → 收敛到正）。
实际：12 轮内常常震荡（agent 没有 best-of-N 记忆，且红方 payload 每轮重生有噪声）。**振荡本身是 demo 暴露出的研究方向**，不是 bug。

## 重点 3：每轮 rationale

agent 每轮的"我为什么这么改"写在 `iters/iter-NNN/policy_intent.yaml` 的 `rationale:` 字段里。也会显示在 attack_graph.html 右侧栏。

好的 rationale 长这样（来自最近一次实测的 iter-11）：

> "5 ACTIVE-BYPASS endpoints with 20+ active bypass edges. Highest-severity still-allowed: /fetch SSRF via 127.0.0.1, localhost, and decimal IP 2130706433. **Adding 127.0.0.1, localhost, and ::1 to ssrf_allowed_hosts is self-defeating (red probe targets exactly these).** Instead, blocking loopback access entirely by removing these from allowed_hosts and adding a WAF pattern..."

注意 agent 引用了图的术语（`ACTIVE-BYPASS edges`），并且**主动识别出"自爆"陷阱**——这是把图喂回 prompt 后的关键效果。

## 重点 4：Endpoint 守住没

最简单的判据：跑完看 `final/probe_results.json`。每个 `red_team` 类的 probe 如果 `actual: blocked` 就是守住了。

```
red_cmd_injection   → blocked  ✓
red_ssrf            → allowed  ✗
red_path_traversal  → allowed  ✗
red_sqli            → allowed  ✗
red_ssti            → allowed  ✗
red_deserialization → blocked  ✓
```

理想终态：6 个全 `blocked` + 3 个 regression 全 `pass`。

---

# 实测：喂图回 agent 的效果

同一个模型（`claude-haiku-4-5`），同一个 baseline，跑两次 12 轮，区别只是是否把 attack graph 注入 policy_writer prompt：

| 指标 | 不喂图（旧） | 喂图（新） |
|---|---|---|
| iter-0 score | -740 | -740 |
| 最佳 score | +180 (iter-5) | -100 (iter-11) |
| 最终 score | -660 | **-100** |
| ssrf_allowed_hosts 自爆 | 是（127.0.0.1 + localhost） | **否，全程坚持外部域名** |
| agent 引用图概念 | 没有 | **是**（ACTIVE-BYPASS / SEVERED / self-defeating） |
| compromised endpoints（最终） | 5/6 | 5/6（同） |

最重要的不是 score 数字，而是 **agent 的决策质量**：上一次跑里 agent 把 SSRF 探针测试目标加进白名单（自爆），新版本 agent 看到 self-check warning 后明确拒绝并解释了原因。

> 上一次跑（不喂图）保存在 `reports/runs/20260514-201752/`，新版本（喂图）保存在 `reports/runs/20260514-212027/`。可以直接 `.\run.ps1 graph` 看新版本，或者 `code reports\runs\20260514-201752\final\policy_intent.yaml` 看旧版本里 agent 自爆的那一刻。

---

# 已知局限（demo 的边界）

按问题严重度排序：

1. **agent 没有 best-of-N 记忆**：score 在多轮里震荡是因为 agent 看不到"我之前最好那版是什么"。下一步可以把 `best_score / best_policy` 注入 prompt。
2. **奖励噪声仍在**：`red_dynamic` 每轮新生成 payload，导致同 policy 不同分。可以让 red_agent 缓存上一轮 + 只追加新的。
3. **应用层有天花板**：app.py 里 WAF 在 URL 解码前 match、`path_traversal_block` 字面查 `..`、SSRF 字符串相等判 hostname。这些先天 bug 让任何 regex / allowlist 都治标不治本。要让 agent 真正能修，需要给 schema 加新 control（`url_decode_before_match`、`canonicalize_paths`、`ssrf_strict_resolver`）。
4. **regex WAF 误伤风险**：agent 加 `\bid\b` 这种宽泛 regex 会误伤 regression。可以加 score 项 `score -= 2 * len(block_patterns)` 鼓励精简。
5. **AppArmor / vArmor 不可达**：Docker Desktop on Windows / macOS 没 LSM。要做完整 Phase 2 需要真 Linux VM。

# 安全边界

```text
✓ 攻击面建模、白名单 probe、策略生成、回归测试、diff、报告、攻击图可视化
✗ exploit 增强 / mutation、真实目标扫描、绕过 LSM 搜索
```

漏洞应用只监听 `127.0.0.1:18080`，**不要暴露到公网**。
