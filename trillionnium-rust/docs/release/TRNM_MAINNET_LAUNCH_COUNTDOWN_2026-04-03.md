# TRNM Mainnet Launch Countdown (2026-04-03)

适用快照：`main@bb83dd6a3`

## Truth-source boundary

本文件回答的问题是：

> **基于当前 `main` 代码与已集成主线，距离 public mainnet release 还差什么，最短发射路径应该怎么排。**

引用本文件时，仍必须同时记录当下的：

- `git rev-parse origin/main`
- `RELEASE_READINESS.md`
- `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`

并且不要把本文顶部的固定 `main@...` 快照字符串当作长期 truth source 复用；每次引用 launch countdown 结论时，都应重新记录当下的 `origin/main`，避免把过期 snapshot 误当成当前 GO / NO-GO 依据。

---

## 当前结论

**结论：仍然 NOT release-ready。**

但当前 `main` 的阶段已经比“lane 分叉推进期”更靠前：

- 36 条 lane 的增量已吸收进主线；
- 当前仓库已回到单主线状态；
- 主链、Web4、contracts 三簇工作都已进入统一主线；
- 当前主要差距已经不再是 branch fragmentation，而是 **production perimeter closure**。

因此，当前最准确的阶段名是：

> **late RC-prep / prelaunch-closure**

而不是：

> **public mainnet candidate**

---

## 一句话判断：现在还差多少

如果按工程收口包来数，而不是按“还差多少提交”来数，当前 `main` 仍大致还差：

- **6 类 P0 blocker**
- **1 个 integrated prelaunch rehearsal / GO-NO-GO package**
- 若 Day-1 scope 还包含 oracle / bridge / verifier productization，再额外加 **3 个 P1 package**

也就是说：

> **主线已经足够强，差的不是“代码有没有”，而是“能不能作为公共主网被安全、可解释、可运维地发出去”。**

---

# Part I — 最短发射路径（Shortest Launch Path）

下面不是“理论上都重要”，而是按：

> **哪几件事最能最快把项目从 late RC-prep 推向 public-mainnet candidate**

来排序。

## Rank 1 — Public read surface / indexer / explorer / historical read-model

### 为什么排第一
当前 `main` 最像“强链核 + 不够稳定的公共读面”。

代码和 runbook 已经说明：
- RPC/query 面比之前更强；
- explorer scaffold 已经有 operator-facing 占位；
- 但 durable indexer / historical query / stable explorer backend 仍未闭环。

这意味着：

> **哪怕链能跑，公共网络仍然缺少对外稳定可读的面。**

### 当前已具备
- 更完整的 query / adapter / readonly contract 面
- explorer scaffold runbook
- placeholder-only 的 operator handoff 模板，能把当前 bring-up / status / rollback 证据写成不夸大 blocker closure 的 ticket 文本（`trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`）
- 一份 **future-state** 的 durable read service handoff skeleton，已经把 non-placeholder deployment / replay / restore / lag / anchor 证据应如何冻结写清楚，但它只是模板，不是当前 durable read closure 证据（`trillionnium-rust/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md`）
- 更清楚的 Day-1 read API 讨论基础

### 仍缺
- durable indexer boundary
- tx / block / account / event historical read-model
- stable explorer backend/API
- archive / read replica policy
- public read SLO / retention policy
- 一份带 **真实 non-placeholder deployment / replay / restore / lag / durable-read anchors** 的 operator handoff packet；当前仓库虽然已有 durable handoff 模板，但还没有可把 Rank 1 关闭写成 operator-grade evidence 的真实 packet

### 这包的真正 exit criteria
- 一份明确的 **Day-1 minimum public read surface**
- 一条 durable indexer pipeline
- 一份 historical retention / replay strategy
- 一条 operator-facing explorer/indexer deployment path

### 为什么这是最短发射路径第 1 名
因为它最直接决定：
- 外部集成方能否接入
- 运维能否看清链上发生了什么
- 发布后是不是立刻进入“黑箱运维”

---

## Rank 2 — Secure signer / keystore / offline signing

### 为什么排第二
当前 `trnm-cli` 已经明显不是草台：
- 有 keystore path hygiene
- 有 unsafe message fail-closed
- 有不少 signer-side 防呆

但距离 public-mainnet signer story 仍差：
- keystore architecture
- offline signing workflow
- remote signer / HSM / multisig posture
- rotation / compromise response
- operator-safe signing UX

### 当前已具备
- CLI wallet / query / tx MVP path
- keystore path hardening
- offline-signing output hygiene / unsafe char rejection
- signer rotation / compromise SOP 文档雏形

### 仍缺
- approved keystore model
- operator-grade offline signing path
- remote signer / HSM / multisig Day-1 posture
- key rotation + compromise response packet
- signer safety checklist attached to launch packet

### Exit criteria
- 一份确定的 Day-1 signer threat model
- 一条真实可执行的 offline signing path
- 一份 rotation / compromise SOP
- 一份 signer safety checklist

### 为什么排第二
因为：

> **没有 signer story，主网不是“不优雅”，而是“不安全”。**

---

## Rank 3 — Real network formation / sync / join-rejoin

### 为什么排第三
当前 `trnm-node` 在 recovery / state-sync / fail-closed 上已经比早期强得多，但 public network 需要的不只是“代码能恢复”，还要：

- peer discovery
- bootstrap topology
- sync expectation
- lagging/rejoin acceptance criteria
- operator-visible diagnostics

### 当前已具备
- recovery / WAL / checkpoint / state-sync 相关 hardening
- 配置与 fail-closed 语义增强
- 更多 node/recovery 测试

### 仍缺
- public-network peer discovery / bootstrap 管理
- join/rejoin acceptance matrix
- lagging node policy
- abuse/backpressure network handling
- operator-facing sync diagnostics

### Exit criteria
- 一个明确 bootstrap/join/rejoin model
- 一份 sync/catch-up acceptance table
- 一次 realistic multi-node formation rehearsal
- 一套 operator-visible diagnosis flow

### 为什么排第三
因为：

> **没有可信的真实网络语义，链只能算“单机或内测系统”，不能算 public mainnet。**

---

## Rank 4 — Integrated prelaunch rehearsal / evidence / GO-NO-GO

### 为什么它独立成一包
前 1~3 都更偏代码与系统设计；
但真正决定“能不能发”的，最终还要落到：

> **在当前 integrated mainline 上跑出一轮可信的 full rehearsal**

### 当前已具备
- `RELEASE_READINESS.md`
- RC / handoff / rollback / evidence 相关脚本与文档
- release discipline 比早期明显更强

### 仍缺
- 一次基于当前 `origin/main` 的 full-chain rehearsal
- 一份 path-resolved evidence bundle
- 一份正式 GO / CONDITIONAL GO / NO-GO memo
- 一次 rollback drill 绑定到同一 packet

### Exit criteria
- full rehearsal green
- preflight artifact、`summary.txt`、`manifest.txt` 都 path-resolved 并一起入包
- artifact identity 一致，且必须保留 ticket-assigned worktree / branch 绑定证据，而不是只证明“当前 shell 自洽”
- `git_worktree_branch_ref_match=true` 与 `git_status_summary=clean` 被逐项保留
- `summary_generated_at=` 与 `manifest_generated_at=` 分开引用，不可塌缩成一个手抄时间戳
- rollback command preserved
- operator decision packet 完整

### 为什么排第四
因为这一步不是“锦上添花”，而是：

> **没有 integrated rehearsal，前面的代码 hardening 不能自动转换成发布可信度。**

---

## Rank 5 — Unified observability / alerting / SRE plane

### 当前状态
这块已经不是空白：
- minimum observability contract 有了
- starter alerting / dashboard / incident handoff pack 有了
- health/query/metering 比早期强很多

但仍未形成一个 production one-plane：
- unified metrics contract 仍不完整
- alert thresholds 仍偏 starter heuristics
- incident labeling / severity / replay attribution 仍未完全绑定

### Exit criteria
- metrics contract
- dashboard pack
- alert rules pack
- incident workflow tied to replay/evidence

### 为什么排第五
因为 observability 很重要，但如果必须压最短发射路径，**它更像“必须在 rehearsal 前收紧”的发射支持系统**，而不是先于 read surface / signer / network 的第 1 优先级。

---

## Rank 6 — Economics / anti-spam / fee boundary freeze

### 当前状态
这块代码不是没做，恰恰相反：
- anti-spam / mempool fairness / sponsor / retention 已有大量实做

问题在于：

> **还没有真正冻结成 Day-1 public economics tuple**

### 仍缺
- final ingress class split
- sponsor caps / boundaries
- retention pricing rule
- anti-spam floor / fee floor / admission floor
- authority / timelock for prelaunch change control

### Exit criteria
- 一份 Day-1 economics tuple freeze
- 一次 spam/fairness rehearsal
- operator/public wording aligned to actual admission rules
- launch packet 引用绿色经济门禁证据

### 为什么排第六
因为它重要，但更像：

> **发射参数冻结**

而不是今天最先决定“能否成为 public chain”的根问题。

---

## Rank 7 — Validator / operator lifecycle

### 当前状态
这块现在已经有不少 runbook / handoff / bootstrap / rollback 文档，不再是空白。

### 仍缺
- genesis ceremony / validator bootstrap 的完整可执行 packet
- operator replacement / recovery / rotation 路径
- DR / rollback / validator-level operational rehearsal

### Exit criteria
- genesis/bootstrap packet
- validator replacement/recovery runbook
- operator rehearsal evidence

### 为什么排第七
不是不重要，而是：

> **它和 Rank 3 / Rank 4 强相关，通常随 network + rehearsal 一起闭环，而不单独先行。**

---

# Part II — 倒排表（Reverse Countdown）

这里不给具体日期，而是按“必须完成的发射阶段”倒排。

## T-4：Public read surface freeze

目标：把“能跑的链”变成“能被稳定读取的公共链”。

### 必须完成
- 冻结 Day-1 read API surface
- 选定 indexer persistence model
- 形成 explorer/indexer deployment path
- 明确 historical retention policy

### 放行条件
- durable indexer boundary 明确
- historical query not hand-wavy
- explorer 不再只是 scaffold 叙事

### 不达标时禁止做的事
- 不要把 Web4 readonly client 误写成 production explorer backend
- 不要把 scaffold/runbook 当作 blocker 已关闭证据

---

## T-3：Signer + network minimum credible launch boundary

目标：把“可用代码”变成“可安全签名、可可信入网”的系统。

### 必须完成
- signer threat model freeze
- keystore/offline-signing architecture freeze
- peer/bootstrap topology freeze
- join/rejoin acceptance matrix

### 放行条件
- signer path 可执行、可审计、可回滚
- public-network semantics 不再停留在 local/test grade

### 不达标时禁止做的事
- 不要仅凭 CLI hardening 就宣称 signer blocker 已关闭
- 不要仅凭 recovery/state-sync tests 就宣称 public network ready

---

## T-2：Observability + economics freeze

目标：让系统不仅能跑，而且在发射后可观察、可解释、可控。

### 必须完成
- unified metrics / alerting minimum pack
- alert thresholds / severity vocabulary freeze
- Day-1 economics tuple freeze
- spam/fairness rehearsal once

### 放行条件
- operator first-stop dashboard/alert bundle ready
- admission / anti-spam / sponsor boundary 可解释

---

## T-1：Integrated prelaunch rehearsal packet

目标：所有前置 closure 在当前 `origin/main` 上统一落成一次 evidence。

### 必须完成
- full-chain rehearsal
- preflight artifact + saved helper transcript + path-resolved `summary.txt` / `manifest.txt`
- artifact identity consistency check（含 ticket-assigned worktree / branch 绑定）
- rollback drill
- GO / CONDITIONAL GO / NO-GO memo

### 放行条件
- 全链 rehearsal green
- `go-no-go-latest.txt`、helper transcript、`summary.txt`、`manifest.txt` 都已落成可引用路径
- `git_worktree_path=`、`git_worktree_branch_ref=`、`git_expected_worktree_branch_ref=`、`git_worktree_branch_ref_match=true`、`git_status_summary=clean` 在 preflight / summary / manifest 三段证据里一致
- `summary_generated_at=` 与 `manifest_generated_at=` 分开保留，且 memo 同时记录当下 `git rev-parse origin/main`
- rollback command 明确
- operator packet 自洽

---

## T-0：Public mainnet claim

只有当以下全部成立时，才可讨论 public mainnet claim：

- read surface closed
- signer path closed
- network formation closed
- observability minimum closed
- economics freeze closed
- validator/operator lifecycle closed enough for launch scope
- integrated rehearsal packet green

在此之前：

> **只能说“主线已进入 prelaunch closure”，不能说“public mainnet ready”。**

---

# Part III — 最短发射路径：先打哪 3 个最划算

如果只允许优先推进 3 个方向，我的建议是：

## Priority A — Public read surface / indexer / explorer
因为这是当前最弱板，也是最容易被外部感知的短板。

## Priority B — Secure signer / keystore / offline signing
因为它决定主网是否有 operator-safe launch story。

## Priority C — Real network formation / sync / join-rejoin
因为它决定系统是否真是 public network，而不是单机/内测 runtime。

### 为什么不是先 observability / economics
不是因为它们不重要，而是：
- observability 更像发射支撑平面
- economics 更像发射参数冻结

如果 A/B/C 还没收口，后两者即使先做，也不太能把项目从 RC-prep 推成 public candidate。

---

# Part IV — 最终一句话

> **当前 `main@bb83dd6a3` 已经证明 TRNM 是一条正在收口的主线，而不是分叉试验场。**
> **但它距离 public mainnet release，仍然不是“差几个 PR”，而是仍差一轮 production-perimeter closeout：6 类 P0 + 1 个 integrated prelaunch packet。**
> **最短发射路径应优先打：read surface / signer / network。**
