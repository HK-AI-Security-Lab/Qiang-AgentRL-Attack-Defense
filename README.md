# AutoPatch-RL

LLM agent 自己改防御策略的小型 demo。**Heuristic-RL 风格**：奖励信号不是更新 NN 权重，而是更新 `policy_intent.yaml` + 编译产物。

```text
state   = 当前 policy_intent + probe 结果 + kill chain + 历史
action  = 改 policy_intent.yaml（每轮一个 control 类别）
reward  = high-risk probe blocked + regression pass + 策略最小
```

## 这个 demo 想证明什么

1. **LLM 能做 RL 闭环**：不训练、不改权重，只靠 in-context state 反馈，agent 也能在多轮里把一个故意搞砸的容器配置一步步收敛回正确状态。
2. **替代专家做配置审计**：iter-0 是一个真实事故级别的错配（SYS_ADMIN cap、unconfined seccomp、host root 挂载、docker.sock 暴露）。**agent 应该在 1 轮内识别并切断所有 escape 边**，把"被打穿到宿主"的风险（host_owned）从 YES 拉到 NO。
3. **白盒 probe 是裁判**：LLM 只能改 yaml，不能评分。14 个固定 shell probe 跑真实容器、看真实退出码。所有"防住没"由确定性程序判定，避免 LLM 自评幻觉。
4. **kill chain 是反馈通道**：每轮把 5 层攻击图（L1 entry → L5 host）的边状态做成 attack_graph，既给人看（demo 价值），又喂回 agent prompt（让它点名"切第 N 条边"，避免乱拍 regex）。

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
  orchestrator.py        主循环（防御者自我修复）
  attack_graph.py        5 层 kill chain DSL + reachability 求解 + history 合并
  attack_graph_html.py   渲染独立 HTML（自包含 SVG，离线可看）
  policy_compiler.py     policy_intent.yaml → docker run 命令
  probe_runner.py        跑白名单 probe
  judge.py               评分 + 终止条件
  runner.py              容器生命周期
  state_store.py         落盘
agents/
  policy_writer.py       LLM agent（看 kill chain → 生成下一版 policy）
  reporter.py            最终 markdown 报告
  prompts/               agent system prompt
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
probe_runner ── 14 个固定 probe (5 容器 + 6 应用 + 3 regression) → results JSON
   │
   ▼
attack_graph build ── 5 层 kill chain（带 history 标签）
   │
   ▼
judge ── score + is_terminal? + 早停（host 安全 + graph 稳定 2 轮）
   │
   ├── 终止 → reporter 写 report.md + attack_graph.html
   ▼
policy_writer (LLM) ── 看 kill chain + self-check warnings → 新 policy_intent.yaml → 下一轮
```

## 为什么要"多轮"

注意：**多轮不是为了显示工作量，是因为有约束**。

- prompt 里有 ONE-CHANGE-PER-ITERATION 规则——每轮只能改一个 control 类别（mounts / caps / seccomp / app_waf 等）。模拟现实工程里"一次只部署一个改动以便回滚"。
- 所以即便 baseline 有 4 个错配，至少要 4 轮才能全部修完。
- 实际跑下来：**iter-1 一轮就能把 host_owned 拉到 NO**（agent 会优先把容器层 escape 边一并切掉），剩下的 1-3 轮在补应用层洞。
- 现在 demo **默认 6 轮**，并且加了**早停**：一旦 `host_owned=False` 且连续 2 轮 kill chain 没变化，自动停。大部分 run 在 3-4 轮内自然停下。

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
MAX_ITERS=6           # 默认 6，早停一般在 3-4 轮触发
```

## 一键启动

```powershell
cd "D:\Codebase\AutoPatch-RL Demo\Qiang-AgentRL-Attack-Defense"

# 第一次跑：自动建 venv、装依赖、构镜像、跑 demo
.\run.ps1
```

第一次跑会按顺序自动：
1. 检查 .env / bash / Docker
2. 创建 `.venv` + `pip install -e .`
3. `docker build -t autopatch-target:vuln target/`
4. `python -m core.orchestrator`（防御 N 轮，N <= MAX_ITERS）
5. 写 `report.md` + `attack_graph.html`
6. 清掉容器

如果 PowerShell 报"running scripts is disabled"，先运行一次：

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## 其他命令

```powershell
.\run.ps1           # 跑 demo（默认）
.\run.ps1 graph     # 打开最近一次的 attack_graph.html
.\run.ps1 report    # 打开最近一次的 report.md
.\run.ps1 down      # 只停容器
.\run.ps1 clean     # 清空 reports/runs 和 policies/generated
.\run.ps1 install   # 只装依赖
.\run.ps1 build     # 只构建镜像
```

跑一次 demo 大概 2-6 分钟（取决于 LLM 延迟和早停时机）。每轮 1 次 LLM 调用 + 14 次 probe + 1 次容器重启。

---

# 怎么解读运行结果

每次跑完 `reports/runs/<时间戳>/` 下面会有：

```
reports/runs/<ts>/
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
    │   ├── probe_results.json          14 个 probe 真实 stdout/exit
    │   ├── attack_graph.json           ★ 这一轮的 kill chain（json 形式）
    │   ├── score.json                  分数
    │   └── diff.md                     与上一轮的策略 diff
    └── iter-NNN/...
```

## 重点 1：attack_graph.html

`.\run.ps1 graph` 打开。这是最直观的入口。

**这是一张 5 层 kill chain 图**。每轮渲染一帧，拖滑块看 agent 改 policy 怎么逐条切断攻击路径。

### 5 层结构（垂直从上到下）

```
L1 Initial Access        6 个端点（前门）：/ping /fetch /read /search /render /load
        │ shell injection / SSRF / traversal / SQLi / SSTI / pickle.loads
        ▼
L2 Capability            拿到的能力：shell_exec / http_egress / file_read / db_read
                                     / python_eval / pickle_rce
        │ subprocess / template evals / open() / DB read
        ▼
L3 Container Compromise  容器内动作：read_shadow / read_kallsyms / create_userns
                                     / read_host / docker_sock / metadata_ssrf
        │ chroot / docker API / kernel ROP / mount via SYS_ADMIN
        ▼
L4 Container Escape      跨出容器：chroot_host / docker_sock_rce / kernel_exploit
                                  / sysadmin_escape
        │ host shell
        ▼
L5 Host                  host_owned（终态）
```

### 节点

每个节点是一张卡片，颜色编码：

- **红色填充** = 这一轮攻击者**已经能到达这个节点**（compromised）
- **灰色填充** = 这一轮**到不了**（safe）

reachability 从 L1 自动传播：L1 永远红（任何人都能戳前门），下面的层只有当存在一条状态为 bypassed/reachable 的入边、且源节点也红，才会变红。

### 边

每条弧线是"红方从 source 到 target 的一种攻击动作"，颜色：

| 边样式 | 含义 |
|---|---|
| **红实线** `bypassed` | 这一轮被 probe **实测确认**打穿了（最高优先级） |
| **黄虚线** `reachable` | policy 没切，源节点又红，是一条**没被探针测过但理论上通的路** |
| **绿实线** `severed` | policy 切断了这条边（agent 修复成果） |
| **灰虚线** `blocked` | 这一轮被 probe **实测确认**拦下了 |
| **极淡灰** `unreachable` | 源节点都到不了，这条边是死路 |

附加光晕：
- **红外发光** `regressed` —— agent 之前切过这条边，这一轮又破了（必须查为什么）
- **绿外发光** `novel-severance` —— agent **这一轮第一次**切断这条边（成果展示）

### 怎么用

- 看 **L5 节点（host_owned）** 是不是红的：终极 KPI。一旦它变灰，agent 就**已经把"被打穿到宿主"的风险消除**了。
- 看右侧栏 **Live Kill Paths**：列出从 L1 到 host_owned 的所有活跃路径。0 条 = host 安全。
- 看哪条边是 **绿色** 但旁边的兄弟边还红：意味着 agent 修了部分但没修完
- 拖滑块从 R0 → RN：看红线一条条变绿，看 L5 从红变灰

### 真实 demo 数据例子

`reports/runs/20260514-212027` 这个 12 轮 run（demo 早停加上前的旧产物）：

```
iter-0  host_owned=YES  bypassed=6  severed=0  kill_paths=1   ← baseline 错配
iter-1  host_owned=NO   bypassed=5  severed=3  kill_paths=0   ← agent 一轮搞定 escape
iter-2~11  host_owned=NO ...                                   ← 后续 10 轮基本无变化
```

iter-1 一轮就把"escape 到 host"消除了：agent 删 mounts / drop caps / 切 seccomp，三个一起改，三条 L3→L4 的边同时变绿（newly-severed）。**iter-2 之后 graph 几乎不再变化**——这正是新版 demo 加早停的原因。

## 重点 2：score 轨迹

```powershell
$run = (Get-ChildItem reports\runs | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
Get-ChildItem "$run\iters" -Directory | ForEach-Object {
    $j = Get-Content "$($_.FullName)\score.json" -Raw | ConvertFrom-Json
    "{0}: total={1}" -f $_.Name, $j.total
}
```

理想轨迹：iter-0 大负 → 几轮内大幅上升 → 早停。如果你看到 score 一直震荡 ±100，几乎肯定是 agent 在用 regex 抠 L1→L2 应用层洞——那一层 control surface 不够强（见"已知局限 #2"）。

## 重点 3：每轮 rationale

agent 每轮的"我为什么这么改"写在 `iters/iter-NNN/policy_intent.yaml` 的 `rationale:` 字段里。也会显示在 attack_graph.html 右侧栏。

好的 rationale 引用 kill chain 术语 + 主动避坑：

> "5 ACTIVE-BYPASS endpoints with 20+ active bypass edges. Highest-severity still-allowed: /fetch SSRF via 127.0.0.1, localhost, and decimal IP 2130706433. **Adding 127.0.0.1, localhost, and ::1 to ssrf_allowed_hosts is self-defeating (red probe targets exactly these).** Instead, blocking loopback access entirely by removing these from allowed_hosts and adding a WAF pattern..."

注意 agent 引用了图的术语，并且**主动识别出"自爆"陷阱**——这是把 kill chain 喂回 prompt 后的关键效果。

## 重点 4：Endpoint 守住没

最简单的判据：跑完看 `final/probe_results.json`。每个 `red_team` 类的 probe 如果 `actual: blocked` 就是守住了。

```
red_cmd_injection   → blocked  OK
red_ssrf            → allowed  X
red_path_traversal  → allowed  X
red_sqli            → allowed  X
red_ssti            → allowed  X
red_deserialization → blocked  OK
```

理想终态：6 个全 `blocked` + 3 个 regression 全 `pass`。**注意**：典型 6 轮 run 不会全 blocked——容器层一轮就清，应用层 5 个洞需要更多轮 + 更强 control surface（见"已知局限 #2"）。host_owned=NO 才是 demo 的真实 KPI。

---

# 已知局限（demo 的边界）

按问题严重度排序：

1. **agent 没有 best-of-N 记忆**：score 在多轮里震荡是因为 agent 看不到"我之前最好那版是什么"。可以把 `best_score / best_policy` 注入 prompt（待做）。
2. **应用层有天花板**：app.py 里 WAF 在 URL 解码前 match、`path_traversal_block` 字面查 `..`、SSRF 字符串相等判 hostname。这些先天 bug 让任何 regex / allowlist 都治标不治本。要让 agent 真正能修，需要给 schema 加新 control（`url_decode_before_match`、`canonicalize_paths`、`ssrf_strict_resolver`）。**这是 demo 当前最大的已知边界**——容器层一轮收敛，应用层 N 轮也补不完。
3. **regex WAF 误伤风险**：agent 加 `\bid\b` 这种宽泛 regex 会误伤 regression。可以加 score 项 `score -= 2 * len(block_patterns)` 鼓励精简。
4. **AppArmor / vArmor 不可达**：Docker Desktop on Windows / macOS 没 LSM。要做完整 Phase 2 需要真 Linux VM。

# 参考 run（历史对照）

仓库里保留了两份 12 轮历史 run（早停加上之前），互为对照：

- `reports/runs/20260514-201752/` — 不喂 attack graph 给 agent
- `reports/runs/20260514-212027/` — 喂 attack graph + self-check warnings

两份都已 backfill 到当前的 5 层 kill chain schema，可直接 `code reports\runs\20260514-212027\attack_graph.html` 打开对比。喂图版 agent 的 rationale 明显能引用图的术语并避开 SSRF 白名单自爆。

# 安全边界

```text
OK 攻击面建模、白名单 probe、策略生成、回归测试、diff、报告、kill chain 可视化
不做 exploit 增强 / mutation、真实目标扫描、绕过 LSM 搜索
```

漏洞应用只监听 `127.0.0.1:18080`，**不要暴露到公网**。
