# TRNM 并发架构瓶颈图与 8 周技术路线图

> 日期：2026-03-10  
> 基线：当前仓库 `main` 快照 `0b209289`（截至本文收口时 `origin/main` 同步）  
> 口径：本文是**并发 closeout / 8 周路线 truth-source**；当前是否 release-ready 仍以仓库根 `RELEASE_READINESS.md` 为准。  
> 目的：
> 1. 明确 TRNM 当前并发架构的真实瓶颈  
> 2. 给出与 Solana / Sui 对标时最该优先追的工程方向  
> 3. 形成未来 8 周可拆解、可验收、可回滚的技术路线图
>
> 入口约定（避免 architecture / reports / development 互相越权）：
> - 当前是否 release-ready：看仓库根 `RELEASE_READINESS.md`
> - 开发排期 / lane 调度 / 下一步执行：看 `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`
> - ZKP 平台专题真相源：看 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`
> - benchmark closeout 方法、统一产物与 micro→system bridge：看 `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`
>
> 本文负责 **并发瓶颈判断、对外并发 closeout 口径、8 周路线**；若只需要 benchmark 方法，不要把本文当成 benchmark closeout 细节手册。

---

## 0. 执行摘要

> 入口约定：
> - 当前发布/就绪真相源：`RELEASE_READINESS.md`
> - 当前并发 closeout / 8 周路线：本文
> - 当前对外 TRNM vs Solana vs Sui 对标口径：`docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md`

TRNM 当前已经具备：

- 对象级 `read_set / write_set` 冲突检测
- 多策略并发分组（`Original / FootprintDesc / HotBucketInterleave / AutoAdaptive / AggressiveGreedy`）
- lane-aware ingress / mempool（`Normal / Critical`）
- pre-exec / commit / `state_root()` 热路径的一轮系统性减负
- challenge / resolve / governance 路径上的多项 fail-closed 与原子性修复

但若以“并发架构效率”对标 Solana / Sui，TRNM 当前仍处于：

> **并发设计已成型，但状态执行后端仍未工业化。**

更具体地说：

- **调度器思路**已经是正经并发链问题空间；
- **执行器热路径**已经不再是朴素串行；
- **真正的上限**仍主要卡在：
  - 状态复制成本
  - 热点对象退化
  - `state_root()`/事件记账重复成本
  - 系统级 E2E 吞吐口径尚未闭环

因此未来 8 周最合理的目标不是“空喊追平 Solana/Sui”，而是：

1. 把 **TRNM 从高质量工程 alpha** 推到 **可量化 benchmark / closeout 的 pre-beta**；
2. 把“并发架构是对的”推进到“并发收益可以稳定测出来、解释得出来、复现得出来”；
3. 对外形成一套**不虚标、能自洽、可审查**的对标口径。

---

## 1. 当前并发架构的瓶颈图（Bottleneck Map）

---

### A. Ingress / Mempool 层

#### 当前已具备
- `LaneAdmissionGate`
- `Normal / Critical` lane
- reserve / spillover / anti-starvation 逻辑
- duplicate / backpressure / self-heal

#### 当前主要瓶颈
1. **critical fairness 仍是逻辑敏感区**
   - 虽然本轮已修 `pick_txs_with_critical_guard()` 的 full-backlog fairness，
   - 但该区域仍然耦合：
     - mempool lane reserve
     - block picker
     - node 侧出队顺序
   - 后续任何微优化都可能再次打破 fairness 语义。

2. **mempool 当前仍是“聪明队列”，不是“原生并发索引层”**
   - lane-aware 是好事，
   - 但还不是那种围绕 object hotness / conflict domain 原生组织的数据结构。

#### 对 Solana/Sui 的差距
- **比 Solana**：缺少端到端高吞吐 ingress pipeline（不仅是 gate，而是传播+预排队+执行联动）。
- **比 Sui**：缺少更原生的 object/hot-object 入池与快慢路径分离。

#### 优先级
**P1**

---

### B. Scheduler / Grouping 层（`trnm-executor`）

#### 当前已具备
- 冲突检测基于 `read_set / write_set`
- 多策略分组
- profiling 指标（如 `candidate_groups_scanned`）
- classic / mixed / hot-streak micro-bench

#### 当前主要瓶颈
1. **策略收益还不稳定**
   - 目前不少策略在 bench 上是“接近持平”而不是“稳定显著领先”。
   - 说明问题已经不再是“有没有策略”，而是：
     - 策略是不是打中了真实瓶颈
     - 或被下游状态执行成本吞掉了收益

2. **调度器已经不再是唯一上限**
   - 当前最明显的系统问题，不再只是分组策略本身；
   - scheduler 改进很可能会被 clone / root / rollback 等成本抵消。

#### 对 Solana/Sui 的差距
- **比 Solana**：调度与 runtime/账户系统的联动深度远不够。
- **比 Sui**：对象冲突抽象方向相近，但对象模型和存储层没有同等原生性。

#### 优先级
**P1-P2**

---

### C. Pre-exec 层（`trnm-node`）

#### 当前已具备
- pre-exec 并发路径
- worker 复用池
- 去掉多余 worker-base clone
- 多组并发预执行

#### 当前主要瓶颈
1. **虽然 clone 已减，但 per-tx clone 仍在**
   - 当前已经从“双层 clone”降到了更可接受状态，
   - 但仍未进入真正低复制执行形态。

2. **Pre-exec 仍然是“业务执行 + 状态快照”的复合成本**
   - 不是纯 scheduler 时间。
   - 一旦状态规模扩大，收益仍可能被快照成本吃掉。
   - closeout 时不要只盯 `preexec_elapsed_*`；还应同步看 `preexec_peak_share_ppm`、`preexec_reject_density_avg_milli`、`preexec_reject_active_height_rate_ppm`、`preexec_reject_active_observed_height_rate_ppm`、`preexec_reject_active_height_share_ppm`、`preexec_reject_share_bps` 与 `preexec_conflict_miss_share_bps`，避免把 guardrail 压力误读成“只是平均耗时略高”，或因为 rejects 只集中在少数高度而被全局均值稀释。

3. **Consensus jitter 需要按 active height 观察，而不是只看全局均值**
   - round-change/backoff 若集中爆发在少数高度，`per_height` 或全局平均很容易稀释真实抖动；
   - 因此 block-loop closeout 应优先看 `bft_round_change_density_avg_milli`、`bft_round_change_backoff_density_avg_milli`，并结合 `bft_round_change_active_height_share_ppm` / `bft_round_change_backoff_active_height_share_ppm` 判断它们占平均 finality budget 的比例；
   - 若存在 skipped / no-commit heights，还要把 committed-budget 视角的 `bft_round_change_active_height_rate_ppm` 与 coverage 视角的 `bft_round_change_active_observed_height_rate_ppm` 一起看，并同步核对 `bft_commit_observed_height_rate_ppm` / `bft_skipped_observed_height_rate_ppm`，避免 jitter 因只按 committed heights 摊薄，或因为 commit coverage 自身下降而被误判为“抖动变轻”。
   - proposer fairness 也要把 validator 分布视角与 active-height 预算视角拆开看：`bft_leader_missed_active_validator_share_ppm` 反映 miss 是否已扩散到多数 proposer，`bft_leader_missed_active_observed_height_rate_ppm` 反映覆盖多少观察高度，而 `bft_leader_missed_active_height_share_ppm` 则衡量这些 bursts 对平均 finality budget 的压力；这三者不能互相替代。
   - scheduler fairness stall 不应只看 `critical_wait_blocks_avg` 或全局 `critical_wait_density_ppm`：还要把 `critical_wait_active_heights`、`critical_wait_active_height_rate_ppm`、`critical_wait_active_observed_height_rate_ppm` 与 `critical_wait_density_avg_milli`、`critical_wait_peak_density_ppm`、`critical_wait_active_height_share_ppm` 一起读，避免把只发生在少数高度的 queueing burst 误判成“整体只是轻度等待”。

4. **Rollback 压力也需要看“活跃高度密度 + 覆盖视角 + 预算占比 + 错误占比”，不能只看次数**
   - `rollback_total` 或 `rollback_count_avg` 只告诉你发生了多少回滚，不能说明它们是否集中压在少数高度，或是否已经开始主导 apply-error 面。
   - closeout 时应把 `rollback_peak_share_ppm`、`rollback_density_avg_milli`、`rollback_active_height_share_ppm`、`rollback_active_height_rate_ppm`、`rollback_active_observed_height_rate_ppm`、`apply_error_rollback_share_bps` 一起看；若存在 skipped / no-commit heights，应优先比较 committed-budget 视角的 `rollback_active_height_rate_ppm` 与 coverage 视角的 `rollback_active_observed_height_rate_ppm`，避免把集中回滚压力因为只按 committed heights 摊薄，或因为只看 observed heights 而误判为更广泛失稳。若回滚主要集中在少数高度，还应优先把它解读为 block-loop 稳定性告警，而不是简单的总体错误率波动。

5. **Hot-object 热点也要按 active height + top/tail 拆开看，不能只盯平均 share**
   - `hot_object_share_avg_ppm` 或 `hot_object_top_label_share_avg_ppm` 容易把“只在少数高度集中爆发”的热点摊薄成看起来温和的平均数。
   - closeout 时应把 `hot_object_active_heights`、`hot_object_active_height_rate_ppm`、`hot_object_active_observed_height_rate_ppm` 与 `hot_object_share_*`、`hot_object_top_label_share_*`、`hot_object_active_top_label_share_avg_ppm`、`hot_object_tail_share_*`、`hot_object_active_tail_share_avg_ppm` 一起读：前者回答热点覆盖了多少 committed/observed heights，后者回答热点是“单一标签强主导”还是“长尾同时升温”。
   - 若 skipped / no-commit heights 存在，应优先比较 `hot_object_active_height_rate_ppm` 与 `hot_object_active_observed_height_rate_ppm`；若两者差距明显，再结合 top/tail share 判断这是局部 burst hotspot，还是更广泛的对象面退化。这样可以避免把热点问题误判成平均上可接受，或把单一热点标签误读成整个对象面都同时恶化。

#### 对 Solana/Sui 的差距
- **比 Solana**：缺少更成熟的 runtime / bank / lock / cache 联动。
- **比 Sui**：对象级执行隔离还不够原生，仍依赖较厚的共享状态层。

#### 优先级
**P1**

---

### D. Commit / Rollback 层

#### 当前已具备
- 定向 rollback snapshot
- 不再对每笔 tx 暴力 `state.clone()`
- staged resolve 等特殊路径的语义保留

#### 当前主要瓶颈
1. **已经从“极重”降到“中等偏重”，但仍然不是零代价**
2. **rollback 仍然是热点路径复杂度来源**
   - 因为它直接耦合：
     - task 对象
     - balances
     - pending resolve approval
     - challenge / resolve 特殊语义

#### 对 Solana/Sui 的差距
- 两者都比 TRNM 更接近“执行后端天然支撑回滚/版本化”的范式；
- TRNM 现在仍是在应用层认真优化，而不是底层系统层天然便宜。

#### 优先级
**P1**

---

### E. State / Root / Audit 层

#### 当前已具备
- `state_root_cache`
- 块内 root 复用
- `PendingResolveApproval.task_version` 纳入状态根

#### 当前主要瓶颈
1. **`state_root()` 依然是“单体状态根”语义**
   - 虽然 cache 已经救了很多，
   - 但根本形态仍不是：
     - 增量 subtree root
     - 原生 MVCC state root
     - sharded object root

2. **状态对象结构仍然偏“中心化聚合”**
   - `objects`
   - `balances`
   - `pending_*`
   - `monetary_state`
   都挂在一个 `StateStore` 下。

#### 对 Solana/Sui 的差距
- **比 Solana**：缺少与执行/存储 tightly-coupled 的 state backend 优化。
- **比 Sui**：缺少“对象版本 + 存储模型原生服务于并发”的优势。

#### 优先级
**P0-P1**

---

### F. RPC / Index / Query 层

#### 当前已具备
- SQLite TTL + quota
- RPC timeout
- authoritative vs recent-tail
- log source 扩展

#### 当前主要瓶颈
1. **查询层仍偏“轻 index + 日志拼接”**
   - 比之前可靠很多，
   - 但还不是成熟的链上索引服务体系。

2. **E2E 吞吐评估还没有统一对外口径**
   - 这会直接限制对标 Solana/Sui 时的说服力。

#### 优先级
**P2**

---

## 2. 当前 TRNM 并发效率的现实判断

### 2.1 我会怎么描述它

TRNM 当前不是“高 TPS 公链的仿制品”，而是：

> **面向 AI compute / task settlement 的对象冲突并发链雏形，已经跨过可运行门槛，但仍在把执行后端做便宜的阶段。**

### 2.2 现阶段性能气质

- **对低到中等冲突、任务相对独立的 workload**：
  - 具备真实并发收益
  - 比朴素串行链明显强

- **对高热点 / 高共享状态压力**：
  - scheduler 思路对，但退化仍会较早出现
  - 下游状态/根计算/回滚会更快变成瓶颈

### 2.3 对标结论
- **比普通原型强**：是
- **比大部分“只有 read/write set 概念”的学术原型更成熟**：是
- **达到 Solana / Sui 生产级并发效率**：否

> L04 observability note:
> - 解释 `bft_round_change_backoff_active_height_share_ppm` 时，不要把它当成强制封顶在 100% 的“占比”。
> - 当 round-change backoff 的活跃高度密度已经超过平均 finality budget 时，该指标**应该允许大于 `1_000_000`**，这样共识抖动/退避主导区间才不会被误读为“只是高一点”。
> - `bft_round_change_backoff_wall_share_ppm` 与兼容别名 `bft_round_change_backoff_share_ppm` 表示的是“每个 committed height 的总 backoff wall-time 压力”，不要把它们和 `bft_round_change_backoff_active_height_share_ppm` 混为一谈；前者是 wall-share，后者才是按活跃高度密度折算到平均 finality budget 的信号。

### 2.4 L04 block-loop observability review checklist

为避免在 closeout / release 讨论里把“少数高度集中爆发的抖动”误读成“全局均值还行”，L04 侧建议把 block-loop 观测拆成下面几组一起看，而不是单看某一个 share / avg 字段：

1. **Round-change cluster pressure**
   - 密度：`bft_round_change_density_avg_milli`
   - committed-height 覆盖：`bft_round_change_active_height_rate_ppm`
   - observed-height 覆盖：`bft_round_change_active_observed_height_rate_ppm`
   - commit / skipped coverage 对照：`bft_commit_observed_height_rate_ppm`、`bft_skipped_observed_height_rate_ppm`
   - budget pressure：`bft_round_change_active_height_share_ppm`
   - 用法：先看 active height 覆盖，再用 `bft_commit_observed_height_rate_ppm` / `bft_skipped_observed_height_rate_ppm` 判断分母是否因为 no-commit heights 发生偏移，最后再看 density/share，避免把 jitter 因 committed-height 收缩而误读成真的变轻，或把 skipped-height 扰动误读成更广泛的不稳定。

2. **Backoff severity must keep three views separate**
   - 密度：`bft_round_change_backoff_density_avg_milli`
   - committed-height 覆盖：`bft_round_change_backoff_active_height_rate_ppm`
   - observed-height 覆盖：`bft_round_change_backoff_active_observed_height_rate_ppm`
   - budget pressure：`bft_round_change_backoff_active_height_share_ppm`
   - wall-share：`bft_round_change_backoff_wall_share_ppm`
   - 兼容别名：`bft_round_change_backoff_share_ppm`
   - 用法：`*_active_height_share_ppm` 代表活跃高度密度折算到平均 finality budget 的压力；`*_wall_share_ppm` / `*_share_ppm` 代表每个 committed height 的总 wall-time backoff 压力，不能互相替代。

3. **Leader fairness hotspot review**
   - proposer 扩散面：`bft_leader_missed_active_validators`、`bft_leader_missed_active_validator_share_ppm`
   - height 覆盖：`bft_leader_missed_active_heights`、`bft_leader_missed_active_height_rate_ppm`、`bft_leader_missed_active_observed_height_rate_ppm`
   - 密度 / budget pressure：`bft_leader_missed_density_avg_milli`、`bft_leader_missed_active_height_share_ppm`
   - top-heavy 参考：`bft_leader_missed_top_share_ppm`
   - 用法：不要只看最终 miss 分布；需要同时确认 miss 是少数 proposer 局部问题，还是已经扩散到多数 proposer 且持续压住多个高度。

4. **Scheduler fairness stall review**
   - height 覆盖：`critical_wait_active_heights`、`critical_wait_active_height_rate_ppm`、`critical_wait_active_observed_height_rate_ppm`
   - stall density / burst pressure：`critical_wait_density_avg_milli`、`critical_wait_peak_density_ppm`、`critical_wait_active_height_share_ppm`
   - 兼容总量参考：`critical_wait_blocks_avg`、`critical_wait_blocks_max`
   - 用法：先确认 stall 发生在多少 committed / observed heights，再判断这些 queueing burst 对平均 finality budget 的压力，避免把只打在少数高度的 fairness stall 误读成“整体只有轻度等待”。

5. **Hot-object concentration review**
   - height 覆盖：`hot_object_active_heights`、`hot_object_active_height_rate_ppm`、`hot_object_active_observed_height_rate_ppm`
   - 总热点占比：`hot_object_share_avg_ppm`、`hot_object_share_p95_ppm`、`hot_object_share_max_ppm`
   - top / tail 拆分：`hot_object_top_label_share_avg_ppm`、`hot_object_active_top_label_share_avg_ppm`、`hot_object_tail_share_avg_ppm`、`hot_object_active_tail_share_avg_ppm`
   - 用法：不要只看平均 hotspot share；需要同时判断热点覆盖了多少高度，以及它是单一标签强主导还是长尾对象面一起升温，避免把 burst hotspot 误读成温和平均值。

6. **Pre-exec / rollback guardrail pressure**
   - preexec：`preexec_peak_share_ppm`、`preexec_reject_active_heights`、`preexec_reject_density_avg_milli`、`preexec_reject_active_height_rate_ppm`、`preexec_reject_active_observed_height_rate_ppm`、`preexec_reject_active_height_share_ppm`、`preexec_reject_share_bps`、`preexec_conflict_miss_share_bps`
   - rollback：`rollback_peak_share_ppm`、`rollback_density_avg_milli`、`rollback_active_height_rate_ppm`、`rollback_active_observed_height_rate_ppm`、`rollback_active_height_share_ppm`、`apply_error_rollback_share_bps`
   - denominator 对照：`bft_commit_observed_height_rate_ppm`、`bft_skipped_observed_height_rate_ppm`
   - 用法：先判断 guardrail 压力是否集中在少数高度，再用 commit / skipped observed-height 对照确认 coverage 分母有没有因为 no-commit heights 变化而漂移，最后再判断它是否已经开始主导平均 finality budget / apply-error 面，而不是只看全局平均耗时或总次数。
> - 因为 `bft_round_change_backoff_wall_share_ppm` 是按 **committed height** 摊开的 wall-time 强度，而不是封顶到平均 finality budget 的百分比，所以它在 sustained backoff 场景下**允许大于 `1_000_000`**；出现这种情况时，应把它解读为“每个已提交高度平均消耗了超过 1ms 的 backoff wall-time 压力”，而不是指标失真。
> - 与 `bft_round_change_density_avg_milli`、`bft_round_change_backoff_density_avg_milli` 一起看，优先判断是否出现了 clustered jitter / sustained backoff，而不是只看全局均值。
> - 若存在 skipped / no-commit heights，`bft_round_change_active_height_rate_ppm`、`bft_round_change_backoff_active_height_rate_ppm`、`bft_leader_missed_active_height_rate_ppm` 与 `rollback_active_height_rate_ppm` 反映的是“相对 committed budget 的压力”，应再对照 `bft_observed_heights` 分母下的 `bft_round_change_active_observed_height_rate_ppm`、`bft_round_change_backoff_active_observed_height_rate_ppm`、`bft_leader_missed_active_observed_height_rate_ppm` 与 `rollback_active_observed_height_rate_ppm`，避免把 coverage/backoff burst 覆盖面误读成纯 committed-height 占比，或把集中回滚错误误判成全局普遍抖动。
> - 对 proposer fairness hotspot，不要只盯 `bft_leader_missed_total` 或最终 miss 分布；应同时查看 `bft_leader_missed_top_share_ppm`、`bft_leader_missed_active_validators`、`bft_leader_missed_active_validator_share_ppm`，以及 `bft_leader_missed_active_heights` / `bft_leader_missed_active_height_rate_ppm`、`bft_leader_missed_active_observed_height_rate_ppm`、`bft_leader_missed_density_avg_milli` 和 `bft_leader_missed_active_height_share_ppm`，避免把集中在少数 proposer 或少数高度的 miss 误读成“总体分布还行”或“最终平均 finality 还够看”。

---

## 3. 与 Solana 的对标路线：差在哪

### TRNM 当前与 Solana 相似之处
- 都重视访问集/冲突集
- 都不是纯串行执行
- 都试图用调度来换吞吐

### TRNM 当前落后 Solana 的关键点
1. **没有 Sealevel 那种端到端工业级 runtime 路径**
2. **没有同等级的网络传播/调度/执行/存储 pipeline 协同**
3. **状态执行后端仍偏“应用层优化”，不是“系统层原生高吞吐”**

### 结论
如果今天直接比高压吞吐：

> **TRNM 与 Solana 仍有明显代差。**

但这个代差主要是：
- 系统工程成熟度差
- 而不是“是否理解并发问题”差

---

## 4. 与 Sui 的对标路线：差在哪

### TRNM 当前与 Sui 相似之处
- 更接近对象/任务冲突抽象
- 并发语义上更像“对象级并行”而不是单纯账户锁

### TRNM 当前落后 Sui 的关键点
1. **对象模型还不够协议原生**
   - 对象虽然存在，但状态仍更偏集中式 `StateStore`
2. **共享热点路径仍然太容易回落到中心状态瓶颈**
3. **对象版本/存储/执行的一体化程度不足**

### 结论
与 Sui 比：

> **TRNM 在抽象方向上更接近，但在成熟度与对象原生并发性上仍明显落后。**

---

## 5. 未来 8 周技术路线图

路线原则：
- 不追求“一步追平 Solana/Sui”
- 追求：**每 2 周都有可测收益、可回滚补丁、可复审数据**

---

### Week 1-2：并发口径冻结 + 基线仪表化

#### 目标
把“我们在优化什么”说清楚，并让 benchmark 对外可解释。

#### 任务
1. 建立统一指标面：
   - `scheduler_elapsed_ms`
   - `preexec_elapsed_ms`
   - `commit_elapsed_ms`
   - `state_root_total_ms`
   - `rollback_count`
   - `critical_wait_blocks_p50/p95/max`
   - `group_count`
   - `avg_group_size`
   - `hot_object_share`
   - `bft_round_change_density_avg_milli`（避免整数平均掩盖轻度共识抖动）
   - `bft_round_change_backoff_density_avg_milli`（避免把 backoff wall time 聚合后看不出抖动集中在哪些 active heights）

2. 为 `trnm-node` 增加块级 profiling 输出（默认关）
3. 建立 benchmark 报表模板：
   - classic
   - mixed
   - hot-streak
   - high-conflict hotspot
4. 输出第一版 E2E 说明：
   - micro-bench ≠ TPS
   - 当前只承诺执行内核与块内路径指标

#### 验收
- `trnm-bench` + `trnm-node` 能输出统一 profiling JSON/文本
- 新增一份 `run/bench/closeout-baseline-*.md`

---

### Week 3-4：状态后端降复制（第一阶段）

#### 目标
进一步降低 clone / rollback / root 计算成本。

#### 任务
1. 把 commit rollback 的片段化快照继续泛化：
   - 不只 task / balances / pending resolve
   - 明确“受影响片段”接口层
2. 将 `state_root_cache` 从“单状态缓存”推进到“块内 dirty-aware cache”
3. 对 `StateStore` 写路径建立统一 invalidate / restore 约束测试
4. 建立 `state_root_total_ms_per_block` 回归门禁

#### 验收
- 高冲突 mixed / hot-streak 下，`state_root_total_ms` 显著下降
- rollback 场景下总 wall time 下降，且语义测试全绿

---

### Week 5-6：热点对象降热点 / 快慢路径拆分

#### 目标
让 challenge / resolve / treasury / authority 等路径不那么容易拖垮整块并发度。

#### 任务
1. 梳理共享热点对象：
   - challenge escrow
   - forfeit treasury
   - worker slash treasury
   - resolve authority / pending approvals
2. 给热点路径打 `hot_object` profiling
3. 评估两类轻量改造：
   - 对象拆分（更细粒度）
   - 快慢路径拆分（非共享对象快走，共享路径慢走）
4. 先做一项最小可回滚实验，不上默认

#### 验收
- 输出热点对象榜单
- 至少一组 workload 下，group_count 不变但 wall time / hot contention 明显下降

---

### Week 7：E2E closeout 与对标口径落地

#### 目标
从“架构上看起来不错”推进到“对外能解释自己现在到哪一步”。

#### 任务
1. 建立第一版 E2E closeout 文档：
   - 测试硬件
   - 负载模型
   - 指标定义
   - 不可比项说明
2. 对比 Solana / Sui 采用同类维度：
   - 并发单元
   - 热点退化机制
   - scheduler 作用边界
   - 状态后端特征
3. 输出 TRNM 当前定位：
   - 工程 alpha / pre-beta
   - 不宣称 production parity

#### 验收
- 新增对外审阅版对照文档
- `RELEASE_READINESS.md` 同步一条当前并发 closeout 结论

---

### Week 8：收口与路线决策

#### 目标
决定 TRNM 后续是：
- 继续沿当前状态后端迭代，还是
- 进入更深的对象化 / shard / MVCC 路线

#### 任务
1. 汇总 8 周数据：
   - 哪些优化稳定有效
   - 哪些只是局部 gain
2. 做一次 owner review：
   - 是否继续投入 scheduler 微优化
   - 是否转向状态后端大改
3. 冻结下一阶段技术主线

#### 验收
- 新增 `docs/reports/TRNM_CONCURRENCY_CLOSEOUT_2026-03-xx.md`
- 明确下一阶段架构决策

---

## 6. 优先级清单（按收益/风险比）

### P0
1. `StateStore` 降复制 / rollback 泛化
2. `state_root()` dirty-aware 降成本
3. 统一块级 profiling 指标

### P1
4. 热点对象 profiling 与拆分实验
5. 继续稳定 critical fairness / lane QoS closeout
6. 建立 E2E closeout 口径

### P2
7. RPC / query / index 更强工程化
8. 文档 / release truth-source 持续跟上主线

---

## 7. 最后一句

TRNM 现在最需要的，不是再证明“自己懂并发”，而是：

> **把并发收益从“代码里有设计”推进到“在统一指标下可稳定观测、可复现、可对标”。**

只有做到这一步，和 Solana / Sui 的比较才会从“架构讨论”变成“工程事实”。
