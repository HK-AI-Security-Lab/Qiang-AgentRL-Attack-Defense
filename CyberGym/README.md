# CyberGym — Base Model + Harness 攻击图 PoC

按你设计文档里的 **Base Model（大模型翻译层）+ Harness（固化图引擎）** 解耦架构做的小型 demo。

```
新 CVE 情报 ──▶ Base Model (LLM)         能力表 JSON
                  │ JSON schema 强约束        │
                  ▼                            ▼
          affected_node_type / pre / post / cvss
                                                │
inventory.yaml ──▶ Harness (确定性 Python) ◀───┘
                                                │
                          ▼                     ▼                  ▼
                  injects VULN_EXPLOIT     finds kill paths   ranks chokepoints
                                                │
                                                ▼
                          attack_graph.html  +  report.md
```

**核心论点**：LLM 不参与图计算或评分，只做"非结构化文本 → 受控词表 JSON"的翻译。Harness 算法完全确定，召回稳定。

---

## 当前能跑通什么

`.\run.ps1 demo` 一键端到端，约 30 秒（不含 Base Model 调用，那一步在 `fresh` 模式下额外 30-60 秒）：

1. 加载 `inventory/sample.yaml`（19 节点 / 33 静态边的 toy 电商系统）
2. 读 `data/capability_table.json`（8 条 Base Model 翻译好的能力表）
3. 注入 19 条 `VULN_EXPLOIT` 边
4. 枚举 15 条从 `internet` 到关键资产的 kill path
5. 排序 5 个 chokepoint
6. 渲染 `out/attack_graph.html`（5 层垂直 SVG，可点节点、可选 path 高亮）
7. 写 `out/report.md`（"修 api_gateway 可切 12/15 条高危路径"那种）

最近一次跑的真实输出：

| rank | node | kind | paths_cut |
|---:|---|---|---:|
| 1 | `api_gateway` | service | **12 / 15** |
| 2 | `order_svc` | service | 7 / 15 |
| 3 | `user_db` | service | 2 / 15 |
| 4 | `search_svc` | service | 2 / 15 |
| 5 | `postgres-image` | workload | 2 / 15 |

---

## 目录结构

```
CyberGym/
├── inventory/
│   └── sample.yaml          # toy 4 层资产 + 静态基线边
├── base_model/
│   └── translate.py         # LLM 翻译器（OpenAI 兼容 API），强 schema 校验
├── harness/
│   ├── graph.py             # YAML → networkx MultiDiGraph
│   ├── inject.py            # 能力表 → VULN_EXPLOIT 边
│   ├── search.py            # BFS 枚举 kill path + 评分
│   ├── cut.py               # path-cut + betweenness 找咽喉点
│   └── render.py            # 5 层垂直 SVG HTML（自包含，离线可看）
├── scripts/
│   ├── pipeline.py          # 端到端编排器
│   └── generate_sample_data.py  # 已有的 100 task fixture 生成器
├── data/
│   ├── sample_tasks.json    # 100 个统一 schema 的 task
│   ├── exploitbench_100.json
│   ├── capability_table.json   # Base Model 输出（8 条）
│   └── raw/                    # 上游 dataset 原文
├── schemas/
│   └── security_task_schema.yaml
├── out/                     # pipeline 输出（attack_graph.html + report.md + paths.json + chokes.json）
├── guide.md                 # 设计稿原文
├── README.md                # 本文件
└── run.ps1                  # Windows 一键入口
```

---

## 节点 / 边设计

### 4 层（+ L0 入口）

| 层 | 节点类型 | 例子 |
|---|---|---|
| L0 Entry | `entry` | `internet`（合成节点，所有路径起点） |
| L1 Product | `product` | `order_system`、`search_system`（带 P0/P1 criticality） |
| L2 Service | `service` | `api_gateway`、`order_svc`、`user_db` |
| L3 Workload | `workload` | `order-app-image`、`postgres-image`（带 packages） |
| L4 InfraNode | `infra_node` | `node-edge-01`、`node-app-01`（带 kernel_version） |

### 边类型

**静态基线**（YAML 手写或 inventory 字段隐式生成）：

| 类型 | 方向 | 来源 |
|---|---|---|
| `NETWORK_REACH` | service → service | YAML `edges:` |
| `IAM_BINDING` | service → service | YAML `edges:` |
| `DATA_FLOW` | service → service | YAML `edges:` |
| `BELONGS_TO` | service → product | 隐式 (service.product) |
| `RUNS_AS` | service → workload | 隐式 (service.workload) |
| `DEPENDS_ON` | workload → infra_node | 隐式 (workload.deployed_on) |

**动态注入**（Harness 根据能力表生成）：

| 类型 | 方向 | 含义 |
|---|---|---|
| `VULN_EXPLOIT` | source → affected_node | 针对该 affected_node_type 节点的 CVE 利用 |

---

## Base Model 输出 schema

每条能力表条目（`data/capability_table.json` 的元素）：

```json
{
  "task_id": "exploitbench:v8-cve-2024-6100",
  "cve_id":  "CVE-2024-6100",
  "affected_node_type": "Service",
  "pre_condition":  ["network_reach", "untrusted_input"],
  "post_condition": ["escape_to_host", "rce"],
  "cvss": 9.2,
  "exploit_maturity": "poc",
  "match_hints": {
    "project_name": "chromium_v8",
    "language":     "cpp",
    "vuln_type":    "logic_error"
  },
  "rationale": "WASM canonical-type bug in V8 -> sandbox escape + rce",
  "source": "llm"
}
```

枚举值固定：

- `affected_node_type ∈ {Service, Workload, InfraNode, RANNode, UE}`
- `pre_condition  ⊆ {network_reach, local_low_priv, local_root, auth_user, physical_access, untrusted_input}`
- `post_condition ⊆ {rce, info_leak, auth_bypass, privilege_escalation, escape_to_host, denial_of_service, data_tamper, mitm}`
- `exploit_maturity ∈ {unproven, poc, functional, in_the_wild}`

任何越界值会触发 1 次重试，再失败回退到 `_heuristic_translate()`（rule-based fallback，保证 demo 不会因 LLM 失联而崩）。

---

## 怎么运行

### 前置依赖

复用父项目的 venv（`..\.venv\`），只需要 `networkx` 和 `pyyaml`：

```powershell
cd "D:\Codebase\AutoPatch-RL Demo\Qiang-AgentRL-Attack-Defense\CyberGym"
.\run.ps1 install
```

需要 `OPENAI_API_KEY`（云雾或任意 OpenAI 兼容 API）。父项目的 `.env` 会被自动加载。

### 一键入口

```powershell
.\run.ps1                # 用缓存的 capability_table.json 跑（最快）
.\run.ps1 fresh          # 重新调 Base Model 翻译 8 个 task，再跑
.\run.ps1 translate      # 只翻译，不跑 Harness
.\run.ps1 graph          # 浏览器打开 out\attack_graph.html
.\run.ps1 report         # 打开 out\report.md
```

### 单步调用（debug 用）

```powershell
..\.venv\Scripts\python.exe -m harness.graph     inventory\sample.yaml
..\.venv\Scripts\python.exe -m harness.inject    inventory\sample.yaml data\capability_table.json
..\.venv\Scripts\python.exe -m harness.search    inventory\sample.yaml data\capability_table.json
..\.venv\Scripts\python.exe -m harness.cut       inventory\sample.yaml data\capability_table.json
..\.venv\Scripts\python.exe -m harness.render    inventory\sample.yaml out\topology.html
..\.venv\Scripts\python.exe -m base_model.translate data\sample_tasks.json -n 8
```

---

## 怎么读 attack_graph.html

`.\run.ps1 graph` 打开。

- **5 个水平条带**：上到下 L0 → L4
- **节点底色**：按 kind 区分（service 蓝、workload 灰、infra_node 深灰、product 绿、entry 红）
- **节点边框**：默认无；选中节点 = 黄；chokepoint = 黄外发光；激活 kill path 上的节点 = 红外发光
- **边颜色**：
  - 蓝实线 `NETWORK_REACH`
  - 黄虚线 `IAM_BINDING`
  - 紫点线 `DATA_FLOW`
  - 灰实线/虚线 `DEPENDS_ON / RUNS_AS`
  - 绿虚线 `BELONGS_TO`
  - **红实线 `VULN_EXPLOIT`**（动态注入）
- **右侧栏**：
  - Inventory Stats（总览数字）
  - Top Chokepoints（点击 = 选中该节点）
  - Kill Paths（点击 = 高亮整条路径，把无关边变暗）
  - Selected Node（attribute + 邻接边 dump）

---

## 已知局限（当前 PoC 的边界）

按严重度排序，跟设计文档里"4 周路线"的 Week 3-4 工作量对应：

1. **inventory 是手写 toy** —— 没接 K8s API / Kafka 实时同步；想验证规模化，下一步要写 `inventory_sync/k8s_informer.py` 把 namespace + Deployment + NetworkPolicy 转成 inventory.yaml。
2. **VULN_EXPLOIT 只看 project name 关键词** —— 真正需要按 `kernel_version` 范围、`packages` 版本号区间匹配。当前如果一个 InfraNode 升级了内核但能力表没标范围，会假阳性。
3. **kill path 用 `all_simple_paths`** —— 这个是指数级别的，规模上去（节点 > 200）必须换成 BFS + 提前剪枝。设计文档 §5.3 已经提了"预剪枝"，留待 Phase 5。
4. **没有 RAN 场景** —— 节点和边类型在 `affected_node_type` 枚举里留了 `RANNode/UE`，但 inventory 里没有；要演无线场景需要在 inventory 里加一组 BTS / BSC / UE 节点 + AIR_INTERFACE / X2_HANDOVER 边类型。
5. **Base Model 只跑 8 个 task** —— 100 个 task 全跑的统计稳定性还没验证；想做"规模化"需要扩到 50+。

---

## 跟父项目 (AutoPatch-RL) 的关系

完全独立。父目录 `..\` 是另一个 demo（防御策略 RL 闭环 + 5 层 kill chain），跟这里共用一份 `.venv` 和 `.env`，但代码不互相 import。如果把这俩看作两条研究线：

- **AutoPatch-RL**：固定 1 个目标（漏洞容器），让 LLM 当防御者迭代改 policy；图静态固定 25 节点，agent 看图改配置
- **CyberGym**：变化的 inventory + 持续涌现的 CVE 情报，让 LLM 当翻译官，Harness 算路径

俩 demo 的攻击图视角是互补的：前者是"防御者视角的 kill chain（哪条边被切了）"，后者是"攻击者视角的 attack graph（哪条边能走通）"。
