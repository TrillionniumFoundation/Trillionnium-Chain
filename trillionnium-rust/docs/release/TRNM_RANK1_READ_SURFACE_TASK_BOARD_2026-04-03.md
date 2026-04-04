# TRNM Rank 1 Task Board — Read Surface / Indexer / Explorer (2026-04-03)

适用快照：`main@bb83dd6a3`

## 定位

本任务板只回答一件事：

> **如何把当前 Rank 1 blocker（public read surface / indexer / explorer / historical read-model）拆成可执行收口包。**

它不等于：
- 整体 mainnet 发布计划；
- Web4 前端产品路线；
- observability / signer / network 的完整收口包。

但它是当前最短发射路径里的 **Priority A**。

---

## Truth-source boundary

引用本任务板时，必须同时参考：

- `RELEASE_READINESS.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_LAUNCH_COUNTDOWN_2026-04-03.md`
- `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`

注意：

> `explorer-service-scaffold` 当前只是 **operator-facing local scaffold / deployment placeholder**，不能被当作 durable indexer / explorer blocker 已关闭的证据。

---

## 当前判断

当前 `main` 已经具备：
- 更完整的 RPC / query 面；
- 更清晰的 readonly contract / adapter / dashboard 数据面；
- explorer scaffold 与 operator-facing bring-up 约定；
- 一些与 read path 相关的 metering / health / runbook 基础。

但仍缺：
- durable indexer boundary
- historical read-model
- stable explorer backend/API
- archive / replay / retention policy
- operator-facing deployment path for a non-placeholder read service
- 对外可承诺的 public read SLO

因此：

> **Rank 1 仍然是最硬 blocker。**

---

# Part I — 任务板总览

## 收口目标（Definition of Done）

当且仅当以下 5 条同时成立时，Rank 1 才可视为关闭：

1. **Day-1 minimum public read surface frozen**
2. **durable indexer pipeline exists**
3. **historical query / storage policy explicit**
4. **explorer backend/API no longer just scaffold**
5. **operator deployment + replay + SLO packet exists**

---

## Task board

### R1-01 — Day-1 Public Read Surface Freeze

**目标**
- 冻结“Day-1 对外公开提供哪些读接口、字段、错误语义、分页语义”。

**必须产出**
- 一份 Day-1 read surface contract 文档
- API surface 清单（task / events / capability audit / normalized audit / block / tx / account）
- 字段稳定性与兼容性边界
- 错误语义与 fail-closed 约定

**当前缺口**
- 查询面分散在 RPC / frontend adapter / docs 中
- 仓内有 readonly contract，但还没形成正式“Day-1 public read contract freeze”

**Exit criteria**
- 有一份单独 truth-source 文档
- 所有 Day-1 查询面都有稳定 schema 与错误码语义
- frontend / operator / future explorer backend 对同一 contract 说同一种话

**建议交付路径**
- 优先从已经存在的 query surfaces 往回收敛，不要重新设计一套全新 API

---

### R1-02 — Query Schema / Error Contract Freeze

**目标**
- 把“能查到数据”升级成“能稳定、可预期地查到数据”。

**必须产出**
- query request/response schema freeze
- pagination / sorting / watermark semantics freeze
- error taxonomy（invalid arg / not found / backend unavailable / partial data / stale snapshot）
- rate limit / timeout / retry semantics 文档

**当前缺口**
- frontend adapter 与 client 语义已有 hardening，但 backend-side public contract 仍不够显式
- normalized audit / events / capability query 语义仍有继续收口空间

**Exit criteria**
- contract tests 可以证明查询语义稳定
- query/client adapter 不再需要靠隐式猜测区分错误语义

**依赖**
- 依赖 R1-01

---

### R1-03 — Durable Indexer Ingestion Pipeline

**目标**
- 把“scaffold”变成真正的 durable indexer。

**必须产出**
- 一个明确的 ingestion source（RPC pull / event stream / block replay / mixed）
- durability boundary（进程重启后不丢已消费位点）
- checkpoint / cursor / replay strategy
- reorg / replay / duplicate event behavior 说明
- 一组明确的 durable-read anchors：`ingestion_source` / `checkpoint_store` / `replay_start_anchor` / `retention_scope` / `archive_owner` / `lag_slo`

**当前缺口**
- 目前的 explorer-service 仍明确不是 durable indexer
- 未见清晰的 indexer crate / persistence boundary

**Exit criteria**
- 存在实际 indexer pipeline（不是仅静态 scaffold）
- 有 cursor/checkpoint 机制
- 能从既有链状态重放并恢复到一致状态
- 上述 6 个 durable-read anchors 已被显式填写；缺任一项都仍按 placeholder / blocker-open 处理

**依赖**
- R1-01 / R1-02

---

### R1-04 — Historical Read-Model Storage Policy

**目标**
- 明确“历史数据怎么存、存多久、怎么 replay、谁负责归档”。

**必须产出**
- historical read-model schema
- storage backend 选择
- retention / archive policy
- replay source / replay cost / replay SLA 说明

**当前缺口**
- historical query 仍是 blocker 文档里的未闭环项
- 没有统一的 archive/read-replica truth-source

**Exit criteria**
- account / tx / block / event 历史查询路径明确
- 能解释“为什么这份历史数据可信、来自哪里、丢了怎么恢复”

**依赖**
- R1-03

---

### R1-05 — Explorer Backend / API Surface

**目标**
- 把“operator-facing local scaffold”升级为“可部署的 explorer backend / read service”。

**必须产出**
- explorer/read-service backend 边界
- health / status / version / upstream linkage contract
- 对外最小 API
- deployable layout（systemd / reverse proxy / env contract / file paths）

**当前缺口**
- 现在的 scaffold 明确不是 production explorer backend
- public explorer 仍缺 backend/API 稳定面

**Exit criteria**
- explorer service 不再只是静态 placeholder
- operator 有真实部署路径
- 外部调用方拿到的是稳定 read service，不是本地静态页模拟

**依赖**
- R1-03 / R1-04

---

### R1-06 — Operator Deployment & Runbook Closure

**目标**
- 把 read surface / indexer / explorer 从“开发者知道怎么跑”变成“operator 知道怎么部署、诊断、恢复”。

**必须产出**
- deployment runbook
- backup / restore / replay / resync runbook
- first-stop diagnosis checklist
- index lag / data gap / stale read / broken cursor 的排障路径
- 一份 handoff packet 模板，能把 placeholder-only 证据与 durable-read anchors 明确区分开

**当前缺口**
- scaffold runbook 存在，但 durable service runbook 还不完整
- operator path 仍偏 placeholder
- placeholder-only handoff packet 模板现已单独收口到 `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`，但 durable-service packet 仍缺
- 目前仓内还没有一份明确的 **durable-service handoff packet** truth-source，去要求 operator 同时抄出：`ingestion_source` / `checkpoint_store` / `replay_start_anchor` / `retention_scope` / `archive_owner` / `lag_slo`，以及 non-placeholder deployment / replay / restore 证据

**Exit criteria**
- operator 不看代码也能 bring-up / diagnose / recover
- read stack 有明确的 oncall 入口
- runbook / handoff note 不再把 scaffold bring-up 证据误写成 durable indexer / historical read-model closure
- 仓内存在一份单独的 durable-service handoff packet truth-source，并与 placeholder-only 模板显式区分
- durable-service packet 至少要求同时出现：6 个 durable-read anchors、deploy/replay/restore 命令、lag/health 证据、以及“非 placeholder backend”声明；缺任一项都不得写成 Rank 1 已关闭

**依赖**
- R1-05

---

### R1-07 — SLO / Performance / Replay Validation

**目标**
- 为 public read surface 建立“能承诺什么”的边界。

**必须产出**
- query latency SLO
- freshness / staleness budget
- replay / resync 时间预期
- index lag thresholds
- 最小 load / replay validation evidence

**当前缺口**
- 还没有看到真正冻结的 public read SLO
- “能跑起来”不等于“可承诺”

**Exit criteria**
- 存在最小 public read SLO 文档
- 至少一轮 load/replay validation 证明当前读面不是纯理论设计

**依赖**
- R1-03 / R1-04 / R1-05

---

### R1-08 — Launch Gate Evidence for Rank 1 Closure

**目标**
- 把前面 7 个包凝结成一个能进入 launch packet 的证据集。

**必须产出**
- read surface freeze evidence
- indexer replay evidence
- explorer deployment evidence
- SLO / lag / health evidence
- rollback / resync commands
- one-page signoff memo
- 6 个 durable-read anchors 的已填值，或显式 blocker note 说明哪些 anchor 仍缺失

**Exit criteria**
- Rank 1 closure 可被 launch packet 直接引用
- 不再需要靠“很多 scattered docs”解释 read surface 已关闭

**依赖**
- R1-01 ~ R1-07

---

# Part II — 最短执行顺序

如果目标是最短路径，而不是并行铺很多面，我建议按下面顺序：

## Phase A — Contract freeze first
1. **R1-01 Day-1 Public Read Surface Freeze**
2. **R1-02 Query Schema / Error Contract Freeze**

原因：
- 如果 contract 不先冻，后面的 indexer / explorer / frontend / operator runbook 都会反复漂移。

## Phase B — Durability next
3. **R1-03 Durable Indexer Ingestion Pipeline**
4. **R1-04 Historical Read-Model Storage Policy**

原因：
- 这是 Rank 1 最硬的“缺真正系统，不只是缺文档”的部分。

## Phase C — Productize the reader
5. **R1-05 Explorer Backend / API Surface**
6. **R1-06 Operator Deployment & Runbook Closure**

原因：
- 先把 durable reader 做出来，再做 deploy/runbook，才能避免 runbook 写在 placeholder 上。

## Phase D — Freeze launchability
7. **R1-07 SLO / Performance / Replay Validation**
8. **R1-08 Launch Gate Evidence for Rank 1 Closure**

原因：
- 没有可量化边界和 evidence，就仍然只是“看起来像收口了”。

---

# Part III — 不要做的事

在 Rank 1 收口期间，建议明确禁止下面几类动作：

1. **不要把 explorer scaffold 当作 blocker 已关闭证据**
2. **不要一边继续改 query 语义，一边写 operator runbook freeze**
3. **不要让 frontend contract 漂移快于 backend/public contract**
4. **不要把 read surface closure 和 full mainnet launch packet 混成一件事**
5. **不要同时大改 indexer schema 与 explorer UI 叙事**

---

# Part IV — 建议的任务归组方式

如果要继续拆成 lane / milestone，我建议按下面 4 组推进，而不是 8 个包完全碎片化：

## Group A — Contract & query freeze
- R1-01
- R1-02

## Group B — Durable data plane
- R1-03
- R1-04

## Group C — Explorer/read service productization
- R1-05
- R1-06

## Group D — Launch evidence
- R1-07
- R1-08

---

# 最终一句话

> **Rank 1 不是“把现有 scaffold 再 polish 一下”，而是要把 TRNM 的公共读面从“可以演示”推进到“可以被 public mainnet 用户和 operator 依赖”。**
> **最短路径应从 contract freeze 开始，穿过 durable indexer / historical read-model，再落到 explorer backend / operator runbook / launch evidence。**
