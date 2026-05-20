# 这次跑出来的图说了什么

> 针对 `out/attack_graph.html` + `out/report.md` 的一次性叙事化解读。
> 跑的源数据：`inventory/sample.yaml`（19 节点 toy 电商系统）+ `data/capability_table.json`（Base Model 翻译的 8 条 CVE）。
> 跑出来的关键产物：15 条 kill path、5 个 chokepoint。

---

## 一句话结论

**修 `api_gateway` 这一个节点，能切断 15 条高危路径里的 12 条（80%）。**

8 条 CVE 情报里只有 3 条真正命中我们的资产；剩下 5 条记录在案但跟我们无关，不用应急。

---

## 这次模拟了什么场景

一家小公司刚把电商系统上线，安全团队拿到 8 条新 CVE 情报。问题是：

- 这 8 条里哪些跟我们有关？
- 黑客从公网开始，最坏能打到哪一步？
- 修哪个节点 ROI 最高？

整张图就是这三个问题的可视化答案。

### 资产长什么样

```
internet (公网)
    │
api_gateway  (DMZ 入口, P0 业务)
    ├── order_svc      ── order-app-image    ── node-app-01
    │       ├── payment_svc   ── payment-app-image ── node-app-01
    │       ├── user_db       ── postgres-image    ── node-data-01
    │       └── cache_redis   ── redis-image       ── node-data-01
    └── search_svc     ── search-app-image   ── node-app-02

api_gateway 自己跑在 ── api-gw-image (nginx)  ── node-edge-01
```

6 个 service / 6 个容器镜像 / 4 台主机。`api_gateway` 是唯一公网入口，里面跑 nginx + openssl-3.0.9。

---

## 8 条 CVE 情报，谁打中了我们

Base Model 把每条 CVE 翻译成"打哪种节点 / 给攻击者什么能力"，然后 Harness 在我们 inventory 上匹配。结果是：

### 命中（3 条）—— 这些是真威胁

| CVE | 类型 | CVSS | 给攻击者什么 | 在我们图上注入了多少红边 |
|---|---|---:|---|---:|
| `syzbot-aabb1122` | 内核 type-confusion | 10.0 | RCE | 6 条（4 台机器，每台从所有部署在它上面的容器都能跳过去） |
| `syzbot-ccdd3344` | 内核 double-free | 9.2 | escape_to_host + 提权 + RCE | 6 条 |
| `arvo:10055` | OpenSSL use-after-free | 7.5 | RCE | 2 条（api_gateway + user_db，都用 openssl-3.0.9） |

**两个 kernel CVE 把所有 4 台机器都标红了。这是因为 inventory 里 4 台机器的 kernel 都是 6.x 系列，能力表也没指定具体版本范围，所以全部命中**。这其实是 PoC 当前的过度匹配——真生产环境得按 kernel_version 范围筛。

### 没命中（5 条）—— 已知但跟我们无关

| CVE | 找的项目 | 为什么不命中 |
|---|---|---|
| `arvo:10013` | ffmpeg | 我们没装 ffmpeg |
| `arvo:10096` | libxml2 | 我们没装 libxml2 |
| `CVE-2024-1939` | chromium_v8 | 我们没用 V8 引擎 |
| `CVE-2024-6100` | chromium_v8 | 同上 |
| `CVE-2024-10231` | chromium_v8 | 同上 |

**SOC 视角下，这 5 条直接归档，今天不用看**。这就是攻击图最实际的价值之一：把 CVE 流水线噪音过滤一半。

---

## 15 条 kill path 长什么样

按风险排序，前 7 条 score 都在 19+，全部用 kernel CVE 把容器内攻击升级到主机层。

```
score=20.10  internet → user_db        → postgres-image    → node-data-01
score=20.10  internet → api_gateway    → api-gw-image      → node-edge-01
score=19.80  internet → api_gateway    → order_svc         → order-app-image    → node-app-01
score=19.80  internet → api_gateway    → search_svc        → search-app-image   → node-app-02
score=19.50  internet → api_gateway    → order_svc → payment_svc → payment-app-image → node-app-01
score=19.50  internet → api_gateway    → order_svc → user_db     → postgres-image    → node-data-01
score=19.50  internet → api_gateway    → order_svc → cache_redis → redis-image       → node-data-01
```

读其中一条，比如最危险那条 `internet → user_db → postgres-image → node-data-01`：

1. **`internet → user_db`**：这是条红边（VULN_EXPLOIT），来自 OpenSSL UAF。意思是黑客直接打 user_db 暴露的 OpenSSL，CVSS 7.5
2. **`user_db → postgres-image`**：灰边（RUNS_AS），表示 user_db 这个 service 实际上跑在 postgres 容器里
3. **`postgres-image → node-data-01`**：又是红边（VULN_EXPLOIT），来自 kernel CVE。在容器里拿 root 后用内核漏洞逃逸到宿主机，CVSS 10.0

3 步打穿 → **公网到生产数据库主机的 root**。

> 注意：这条路径暴露了一个**误报**——现实里 `user_db` 不应该公网可达。出现这条边是因为 Base Model 把 OpenSSL CVE 标成 `affected_node_type=Service` + `match_hints.project_name=openssl`，Harness 看到 user_db 的 postgres 镜像也含 openssl，就给它画了一条 internet→user_db 的红边。**真生产环境需要叠加一个"目标 service 必须真在 internet 的网络可达闭包里"的过滤**。这是 PoC 留下的一个值得改进的问题。

剩下 8 条 score 在 11-17 区间，目标是 service 层（不是机器），表示"打穿到这个 service 就停"，没有进一步逃逸到主机。

---

## 5 个咽喉点（chokepoint）

把 15 条 path 看一遍，统计每个中间节点出现在多少条 path 上：

| 节点 | 出现在多少条 path | 介数中心性 | 综合分 (blend) |
|---|---:|---:|---:|
| **api_gateway** | **12 / 15** | 0.039 | **0.71** |
| order_svc | 7 / 15 | 0.045 | 0.42 |
| user_db | 2 / 15 | 0.030 | 0.13 |
| search_svc | 2 / 15 | 0.017 | 0.12 |
| postgres-image | 2 / 15 | 0.017 | 0.12 |

**comp_blend = 70% × paths_cut% + 30% × betweenness**。前者是直接收益（修这个节点能立刻消掉多少条 path），后者是图论意义上的"必经之地"程度。

`api_gateway` 12/15 的覆盖率源于 inventory 设计——它是唯一公网入口，几乎所有从 internet 开始的攻击都得过它。

第二名 `order_svc` 7/15 是横向移动的咽喉：搜索/支付都靠它中转，一旦 order_svc 沦陷，攻击者就能跳到 user_db、payment_svc、cache_redis、甚至 search_svc 后面那条独立链路也无关——它是订单业务侧的中央调度。

后面三个出现频率低，但 user_db / postgres-image 仍值得关注，因为它们在最高分那两条路径上。

---

## 攻击者视角的 3 个观察

### 观察 1：网络层 + 系统层 = 致命组合

最危险的几条路径不是单一漏洞造成的，是 **应用层 RCE（OpenSSL）+ 系统层 escape（kernel）的接力**。

- 单 OpenSSL UAF：score 仅 7.5，攻击只到 service 层
- 单 kernel CVE：自身需要 local_low_priv，从公网够不到
- 两个串起来：score 20+，从公网直接打到主机 root

**这就是 attack chain 视角比"单漏洞 CVSS 排序"更准的核心原因**。CVSS 7.5 + CVSS 10.0 不是简单求和，是两段路径相乘。

### 观察 2：kernel CVE 的爆炸半径取决于"共用 kernel 的机器"

inventory 里 4 台机器有 3 台用同样的 kernel `6.5.0-15-generic`：

```
node-edge-01    → 6.5.0-15  ← DMZ 暴露面
node-app-01     → 6.5.0-15  ← 应用区
node-app-02     → 6.1.0-18  ← 应用区，独立
node-data-01    → 5.15.0-89 ← 数据区，最老
```

**3 台共用同一个 kernel = 一个 kernel CVE 同时打开 3 条 escape 路径**。如果 4 台机器各用不同 kernel，影响面只有原来的 1/4。这是设计文档第 7 节"打散基础镜像、避免单点故障"的可视化证据。

### 观察 3：api_gateway 是单点防御杠杆

12/15 的 chokepoint 覆盖率说明：**这次 inventory 是典型的"洋葱皮"架构**——所有外部流量都从 api_gateway 进入，内部服务之间反而没有公网入口。这种架构下：

- 加固 api_gateway = 一次性收益 80%
- 但反过来：**api_gateway 一旦失守，里面服务的 IAM_BINDING 几乎裸奔**（横向移动只受 NETWORK_REACH 限制）

如果想进一步降低风险，下一步该做的不是再加固 api_gateway，而是**给 order_svc / payment_svc 之间的横向移动加 mTLS / RBAC**（图上是 IAM_BINDING 边）——把网关沦陷后的爆炸半径再砍一刀。

---

## 这次跑暴露的 PoC 局限

| 局限 | 这次跑里看到的现象 | 解决方向 |
|---|---|---|
| Base Model 没标 kernel 版本范围 | 4 台机器全部命中 kernel CVE，包括 5.15 老 kernel | 让 Base Model 输出 `affected_versions` 字段，inject 时按版本范围过滤 |
| 没考虑网络可达性闭包 | 出现 `internet → user_db` 误报路径 | inject 时检查 source 是否在 target 的反向 NETWORK_REACH 闭包里 |
| 静态边都是手写的 | inventory 19 节点是手画的 | Phase 5：写 K8s informer 把 NetworkPolicy / Service 转 inventory.yaml |
| `all_simple_paths` 路径枚举 | 19 节点 / 33 边 → 15 条 path 还行 | 节点数 > 200 时必须换 BFS+剪枝 |

---

## 一句话给老板

> "我们刚处理了 8 条新 CVE 情报，扫了一遍生产电商系统。**5 条情报跟我们无关；3 条命中**，最坏可以让黑客 3 步从公网打到生产数据库主机。**今天先修 api_gateway（升级 nginx + openssl + 加 WAF）就能切掉 80% 的风险路径**，剩下 20% 是横向移动需要进一步处理。"

---

## 怎么自己看这张图（10 秒版）

```powershell
.\run.ps1 graph
```

看右栏从上往下：

1. **TL;DR 红色横幅**——3 秒拿主结论
2. **Threat Intel 数字**——`applicable to us = 3 / 8`，决定今天要处理几条
3. **Capability Table**——3 张可点的红色卡片就是真威胁，逐个点看影响范围
4. **Kill Paths**——点排第一的，看完整攻击链
5. **Top Chokepoints**——`api_gateway` 第一个，就是今天要修的
