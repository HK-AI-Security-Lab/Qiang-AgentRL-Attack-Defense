# AutoPatch-RL Demo

LLM Agent 自己改防御策略的小型 demo。**Heuristic-RL 风格**：奖励信号不是更新 NN 权重，而是更新 `policy_intent.yaml` + 编译产物。

```text
state   = 当前 policy_intent + probe 结果 + 历史
action  = 改 policy_intent.yaml
reward  = high-risk probe blocked + regression pass + 策略最小
```

## 这个 demo 做了什么（不是 toy）

- **真实漏洞**：`target/app.py` 的 `/ping` 接口是真实的命令注入（OWASP A03 / CWE-78，每年都在事故里出现）。
- **真实错配**：baseline 启动参数包含 `--cap-add=SYS_ADMIN`、`--security-opt seccomp=unconfined`、`-v /:/host:ro`、`-v /var/run/docker.sock:/var/run/docker.sock` —— CTF 和真实事故里的标准翻车姿势。
- **真实防御杠杆**：seccomp profile、capabilities、`--read-only`、`--user`、`--no-new-privileges`、删除危险挂载、app 层 regex WAF。
- **真实可观测**：每条 probe 都返回真实 stdout/stderr/exit_code，不是 mock 的 `{"actual":"allowed"}` 写死值。

## 快速起步（Mac M1）

```bash
# 1. 准备 Docker Desktop（已装 28.3.2，启动它）
open -a Docker

# 2. 配 LLM key（云雾 API，OpenAI 兼容）
cp .env.example .env
# 编辑 .env 填入 OPENAI_API_KEY=sk-...

# 3. 装依赖 + 构镜像 + 跑 demo
make install
make build-target
make demo

# 4. 看报告
make report
```

跑一次大概 1-2 分钟（取决于 LLM 延迟）。每轮一行表格滚出来，最终生成 `reports/runs/<ts>/report.md`。

## 目录

```text
target/        # 漏洞 Flask 应用 + Dockerfile
probes/        # 白名单 probe（attack_surface + regression）
schemas/       # policy_intent / probe_result 的 JSON schema
policies/
  baseline/    # 故意错配的初始 policy_intent.yaml
  generated/   # latest 符号链接指向最近一轮
core/          # orchestrator / runner / probe_runner / compiler / judge / state_store
agents/        # LLM 驱动的 policy_writer + reporter（+ 确定性 fallback）
reports/runs/  # 每次跑的全量输出（policy/probe/score/diff/report）
```

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
probe_runner ── 8 个 probe (5 attack + 3 regression) → results JSON
   │
   ▼
judge ── score + is_terminal?
   │
   ├── 终止 → reporter 写 report.md
   ▼
policy_writer (LLM) ── 新 policy_intent.yaml → 下一轮
```

## 实验记录：claude-haiku-4-5 × 单步约束 × 3 轮收敛

模型：`claude-haiku-4-5-20251001` (via 云雾 API)
约束：每轮只允许改一个 control 类别（mounts / capabilities / seccomp / app_waf / container_security）
耗时：~48s（含 3 次 LLM 调用 + 3 次 docker 重启 + 8×4 轮 probe）

### 每轮详情

| 轮次 | agent 动作 | 新 blocked 的 probe | 仍 allowed | score |
|---|---|---|---|---|
| iter-0 | baseline 错配（非 agent） | proc_kallsyms（kernel 默认屏蔽） | cmd_injection, host_mount, docker_sock, userns | **-230** |
| iter-1 | 删 `/host` 和 `docker.sock` 挂载 | host_mount, docker_sock | cmd_injection, userns | **+170** |
| iter-2 | 启用 WAF，regex `[;&\|` `` ` ``$()]` | cmd_injection | userns | **+370** |
| iter-3 | cap-drop=ALL, seccomp=RuntimeDefault, no_new_privileges | userns | ∅ | **+450** ✓ |

### iter-3 最终 policy（agent 输出）

```yaml
controls:
  container_security:
    run_as_non_root: false
    allow_privilege_escalation: false
    read_only_root_fs: false
    no_new_privileges: true
    privileged: false
  capabilities:
    drop: [ALL]
    add: [NET_RAW]
  seccomp:
    profile: RuntimeDefault
  mounts:
    bind: []           # 危险挂载全删
  app_waf:
    enabled: true
    block_patterns: ['[;&|`$()]']
```

### agent 每轮的 rationale（摘要）

- **iter-1**：`probe_host_mount` 和 `probe_docker_sock` 都是 high severity、都依赖 bind mount。删除 mounts 是最高优先级且零 regression 风险。
- **iter-2**：`probe_cmd_injection` 是剩余唯一的 high severity。启用 WAF 拦 shell metachar，`127.0.0.1` 不含这些字符所以 regression_legit_ping 不会误伤。
- **iter-3**：`probe_userns` 是最后一个 allowed（medium）。`unshare -U` 需要特权或 unconfined seccomp；改成 RuntimeDefault + drop ALL + no_new_privileges 三管齐下。

### 残余风险（agent report 中列出）

1. 应用层 RCE bug 没修（WAF 是缓解不是修复，编码绕过可能存在）
2. 容器仍以 root 跑（`run_as_non_root: false`）
3. 文件系统可写（`read_only_root_fs: false`）
4. 无 AppArmor / vArmor（macOS Docker Desktop 不支持）
5. 无网络策略（容器仍可出站）

完整 report 见 `reports/runs/20260511-224120/report.md`

---

## 关键设计

- **agent 只能改 `policy_intent.yaml`**，不能写 shell、不能改 probe、不能改 compiler。
- **schema 强约束**：LLM 输出过不了 `jsonschema` 就回退到确定性 heuristic，保证 demo 一定能跑完。
- **probe 全白名单**：5 个攻击面 probe + 3 个 regression probe，shell 脚本预先写好。
- **每轮全量落盘**：`reports/runs/<ts>/iters/iter-NNN/{policy_intent.yaml, probe_results.json, score.json, diff.md, docker_run.sh, waf_rules.json}`。

## 安全边界

```text
✅ 攻击面建模、白名单 probe、策略生成、回归测试、diff、报告
❌ exploit 增强 / mutation、真实目标扫描、绕过 LSM 搜索
```

漏洞应用只监听 `127.0.0.1:18080`，不要暴露到公网。

## 完整版路线图

见 [guide.md §9](./guide.md#9-完整版-todo-mvp-跑通后做)：第二个漏洞、真实 K8s+vArmor、网络/seccomp 自动收窄、BPF 热补丁、Web UI、评测对比。
