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
6. 渲染 `out/attack_graph.html`（5 层垂直 SVG，可点节点 / 路径 / CVE）
7. 写 `out/report.md`（TL;DR：修哪、覆盖率多少、CVE 应用情况）

最近一次跑的真实 TL;DR：

> **Patch `api_gateway` (service) first** — it sits on **12 / 15** live kill paths (**80% 攻击面削减**)。
> Threat intel: **3 / 8** ingested CVEs actually land on our inventory (5 not applicable)。

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
│   └── generate_sample_data.py
├── data/
│   ├── sample_tasks.json    # 100 个统一 schema 的 task
│   ├── exploitbench_100.json
│   ├── capability_table.json   # Base Model 输出（8 条）
│   └── raw/
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

| 类型 | 方向 | 含义 |
|---|---|---|
| `NETWORK_REACH` | service → service | 网络可达（防火墙允许 A 访问 B） |
| `IAM_BINDING` | service → service | A 持有调 B 的凭证（service account / DB user） |
| `DATA_FLOW` | service → service | A 往 B 写 / 读数据 |
| `BELONGS_TO` | service → product | service 属于哪个 product（业务归属） |
| `RUNS_AS` | service → workload | service 跑在哪个镜像上 |
| `DEPENDS_ON` | workload → infra_node | 镜像跑在哪台主机 |

**动态注入**（Harness 根据能力表生成）：

| 类型 | 方向 | 含义 |
|---|---|---|
| `VULN_EXPLOIT` | source → affected_node | 攻击者利用某 CVE 从 source 跳到 affected_node |

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

**枚举值固定**：

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
..\.venv\Scripts\python.exe -m base_model.translate data\sample_tasks.json -n 8
```

---

# 怎么看 attack_graph.html

`.\run.ps1 graph` 打开。

页面分两半：左边是 5 层 SVG 拓扑图，右边是 5 块信息面板。下面把每一块怎么读 / 怎么点都说一遍。

## 左半：5 层垂直拓扑图

### 节点（按层）

由上到下五个水平带：

| 层 | 是什么 | 怎么辨认 |
|---|---|---|
| **L0 Entry** | `internet` 合成节点（攻击起点） | 红框、最顶部 |
| **L1 Product** | 业务单元（如订单系统） | 绿框 |
| **L2 Service** | 微服务 / 数据库 | 蓝框 |
| **L3 Workload** | 容器镜像 / 固件 | 灰框 |
| **L4 InfraNode** | 物理机 / 虚拟机 | 深灰框 |

**关键直觉**：攻击者总是从顶部进，向下渗透。L4 被打穿 = 拿到宿主机 = 最坏结果。

### 边（按类型 / 颜色）

| 颜色 | 类型 | 含义 |
|---|---|---|
| **蓝实线** | NETWORK_REACH | 网络可达（防火墙允许 A 访问 B） |
| **黄虚线** | IAM_BINDING | A 持有调 B 的凭证 |
| **紫点线** | DATA_FLOW | A 往 B 写 / 读数据 |
| **绿虚线** | BELONGS_TO | service 属于 product（业务归属） |
| **灰线** | RUNS_AS / DEPENDS_ON | service 跑在哪个镜像上 / 镜像跑在哪台主机 |
| **🔴 红粗实线** | **VULN_EXPLOIT** | **CVE 让攻击者从 A 跳到 B** ← 重点看这种 |

红线就是 Base Model 翻译完之后 Harness 注入的"动态边"。**没有这些红线，整张图只是一张资产清单；加上红线，它才变成攻击图**。

## 右半 5 个信息面板

### 面板 ❶ TL;DR Headline（红橙渐变横幅）

```
TOP RECOMMENDATION
Patch  api_gateway  (service) first — it sits on
 12 / 15  live kill paths ( 80%  attack-surface reduction).
```

打开页面第一眼就看到。这是 SOC 视角的"最重要那个数"——修哪个节点能抵几条路径。

### 面板 ❷ Stats（拆成 Inventory + Threat Intel）

```
┌── Inventory ─────────────────┐    ┌── Threat Intel ────────────────┐
│ nodes                  19    │    │ CVEs ingested               8  │
│ edges (static + vuln)  52    │    │ applicable to us         3 / 8 │  红色加粗
│ products                2    │    │ not applicable              5  │
│ services                6    │    │ VULN_EXPLOIT edges         19  │
│ workloads               6    │    │ kill paths                 15  │  红色加粗
│ infra nodes             4    │    │                                │
└──────────────────────────────┘    └────────────────────────────────┘
```

- **左边 Inventory**：你的资产清单。回答"我有什么"。
- **右边 Threat Intel**：威胁情报覆盖率。
  - `CVEs ingested = 8`：Base Model 总共翻译了多少条情报
  - `applicable to us = 3 / 8`：其中真正能在你 inventory 上落地的有几条
  - `not applicable = 5`：剩下的虽然 Base Model 翻译成功了，但你的资产里没对应目标（比如 V8 / FFmpeg 不在 inventory 里）。**这就是 SOC 视角的关键过滤信号——不要浪费时间应急那些跟你无关的 CVE**
  - `kill paths = 15`：从 internet 到关键资产的活路径数

### 面板 ❸ Top Chokepoints（咽喉点）

```
api_gateway      (service)   cuts 12/15   blend=0.71
order_svc        (service)   cuts  7/15   blend=0.42
user_db          (service)   cuts  2/15   blend=0.13
search_svc       (service)   cuts  2/15   blend=0.12
postgres-image   (workload)  cuts  2/15   blend=0.12
```

按"修这个节点能抵多少条路径"排序。`blend = 70% × path-cut% + 30% × betweenness`——前者是直接收益，后者是图结构上的"瓶颈程度"。

**点一下任一行** → 左侧那个节点变黄高亮。

### 面板 ❹ Capability Table（CVE 情报清单）★ 这次新加的

```
┌──────────────────────────────────────────────────────────┐
│  syzbot-aabb1122                       [InfraNode]       │
│  cvss=10.0 | post: rce | edges injected: 6  (src=llm)    │
│  Kernel type-confusion → RCE                             │
└──────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────┐
│  CVE-2024-6100                            [Service]      │
│  cvss=9.2  | post: escape_to_host, rce                   │
│              | edges injected: 0  [no match] (src=llm)   │  ← 灰显
│  WASM canonical-type bug in V8 → sandbox escape + rce    │
└──────────────────────────────────────────────────────────┘
```

每一条都是 Base Model 翻译出来的一个 CVE。包含：

- **CVE-ID 或 task-id**（红字加粗）
- **affected_node_type 标签**（Service / Workload / InfraNode）
- `cvss` + `post_condition`（攻击者能拿到什么能力）
- **edges injected**：这条 CVE 在 inventory 上注入了几条红边
  - `> 0` = 真打中了你的资产，可点击
  - `= 0` = `[no match]` 标签，灰显，表示"已知但与你无关"
- **source**：`llm` 或 `heuristic` 回退
- **rationale**：Base Model 自己给的一句话解释

**点一下能用的（非 ghost）行** → 左侧攻击图：
- 这条 CVE 注入的所有红边变粗 + 红光晕
- 边的两端节点也变红框
- 其他所有边变灰，背景退场

直接看到"这条情报到底打在哪几个节点上"。

### 面板 ❺ Kill Paths（活攻击路径）

```
internet -> api_gateway -> api-gw-image -> node-edge-01      score=20.10  vuln
internet -> api_gateway -> order_svc -> order-app-image -> node-app-01    score=19.80  vuln
internet -> api_gateway -> order_svc -> payment_svc -> ...   score=19.50  vuln
...
```

15 条，按风险分排序：`max(CVSS) × 业务关键度 × 含漏洞系数 - 路径深度惩罚`。

**点一下任一条** → 整条路径在左侧染红：节点变红框、边变粗红线，**其他所有边和节点变暗**——这是 demo 最直观的演示动作，哪条链是关键链一眼看清。

### 面板 ❻ Selected Node（节点详情）

**点 SVG 上任意节点** → 右侧栏底部显示这个节点的所有属性 + incoming/outgoing 边列表。

```
id:    api_gateway
kind:  service    (layer 2)
auth_method: oauth2
ztn_policy: strict
is_public: True

incoming (3):
  internet -> api_gateway [NETWORK_REACH]
  internet -> api_gateway [VULN_EXPLOIT]    ← 这条是 OpenSSL CVE 注入的

outgoing (4):
  -> order_system [BELONGS_TO]
  -> api-gw-image [RUNS_AS]
  -> order_svc    [NETWORK_REACH]
  -> search_svc   [NETWORK_REACH]
```

看节点在攻击图里的位置和它"承担的责任"。

## 三种点击行为互斥

为了避免高亮互相打架，三种选中状态互斥：

| 你点了 | 效果 |
|---|---|
| 一个 SVG 节点 | 高亮该节点 + 邻接边；其他选中清掉 |
| 一条 Kill Path | 全路径染红，其他变暗；其他选中清掉 |
| 一条 Capability | 该 CVE 所有红边染红，其他变暗；其他选中清掉 |

**再次点同一项 = 取消选中，回到默认（咽喉点黄色高亮）**。

---

## 一次完整演练（建议这样看）

打开 `out/attack_graph.html` 之后：

1. **看 ❶ TL;DR**：3 秒拿到主结论："修 api_gateway 能干掉 80% 风险"。
2. **看 ❷ Threat Intel stats**：8 条情报里只有 3 条命中。剩下 5 条的等价含义是 "这些 CVE 已知，但跟我们没关系，不用应急"。
3. **打开 ❹ Capability Table**：3 条命中的红色卡片就是真正的威胁——
   - syzbot-aabb1122（InfraNode）：内核 RCE
   - syzbot-ccdd3344（InfraNode）：内核逃逸
   - 10055 OpenSSL UAF（Service）：协议库 RCE
4. **逐条点击命中卡片** → 看图里哪些节点变红
   - 点 syzbot-aabb1122 → 4 台 InfraNode 全变红 + 6 条红边（每台机器从所有部署在它上面的容器都能逃过去）
   - 点 OpenSSL → user_db 和 api_gateway 同时变红（这俩 service 都用 openssl-3.0.9）
5. **看 ❺ Kill Paths**：点排第一的 score=20.1 那条
   - 路径变红：`internet → user_db → postgres-image → node-data-01`
   - **意思**：黑客通过暴露的 postgres openssl 漏洞进入 user_db service，进 postgres 容器，再用 syzbot 内核漏洞从容器逃到 node-data-01 主机
6. **回到 ❸ Top Chokepoints**：点 `api_gateway` → 高亮黄色
   - 12 条路径都过它。**先修它就对了**

---

## 已知局限（当前 PoC 的边界）

按严重度排序，跟设计文档里"4 周路线"的 Week 3-4 工作量对应：

1. **inventory 是手写 toy** —— 没接 K8s API / Kafka 实时同步；想验证规模化，下一步要写 `inventory_sync/k8s_informer.py` 把 namespace + Deployment + NetworkPolicy 转成 inventory.yaml。
2. **VULN_EXPLOIT 只看 project name 关键词** —— 真正需要按 `kernel_version` 范围、`packages` 版本号区间匹配。当前如果一个 InfraNode 升级了内核但能力表没标范围，会假阳性。
3. **kill path 用 `all_simple_paths`** —— 这个是指数级别的，规模上去（节点 > 200）必须换成 BFS + 提前剪枝。设计文档 §5.3 已经提了"预剪枝"，留待 Phase 5。
4. **没有 RAN 场景** —— 节点和边类型在 `affected_node_type` 枚举里留了 `RANNode/UE`，但 inventory 里没有；要演无线场景需要在 inventory 里加一组 BTS / BSC / UE 节点 + AIR_INTERFACE / X2_HANDOVER 边类型。
5. **Base Model 只跑 8 个 task** —— 100 个 task 全跑的统计稳定性还没验证；想做"规模化"需要扩到 50+。

## 跟父项目 (AutoPatch-RL) 的关系

完全独立。父目录 `..\` 是另一个 demo（防御策略 RL 闭环 + 5 层 kill chain），跟这里共用一份 `.venv` 和 `.env`，但代码不互相 import。如果把这俩看作两条研究线：

- **AutoPatch-RL**：固定 1 个目标（漏洞容器），让 LLM 当防御者迭代改 policy；图静态固定 25 节点，agent 看图改配置
- **CyberGym**：变化的 inventory + 持续涌现的 CVE 情报，让 LLM 当翻译官，Harness 算路径

俩 demo 的攻击图视角是互补的：前者是"防御者视角的 kill chain（哪条边被切了）"，后者是"攻击者视角的 attack graph（哪条边能走通）"。
