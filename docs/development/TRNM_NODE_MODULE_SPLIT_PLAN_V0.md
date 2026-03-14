# TRNM Node Module Split Plan v0

- 状态：**Draft / executable refactor plan**
- 范围：只针对 `trillionnium-rust/crates/trnm-node/src/main.rs`
- 目标：把当前 `trnm-node` 从单文件巨石结构，拆成**可分步迁移、每一步都能跑 gate、尽量不改语义**的模块化布局

> 约束：
> - 第一阶段只做**结构迁移**，不主动改协议语义
> - 不打穿 `trnm-state` / `trnm-pouw` 已经收口的 live boundary / restore / event semantics
> - 每一刀都必须可独立验证，避免“一次性大搬家”

---

## 1. 为什么 `trnm-node` 必须先拆

当前 `trnm-node/src/main.rs` 约 **12.6k 行**，而且几乎所有核心职责都混在一个文件内：

- config / args
- WAL / checkpoint / recovery
- BFT round / height simulation
- demo mempool builder
- tx pick / critical guard
- event emit / timeout emit
- rollback snapshot / restore / apply
- timeout scanner
- hot-object summary
- pre-exec pool / ordering decision
- 主 block loop / metrics / summary printing
- 内嵌 tests

这已经超过“单文件可维护上限”，并且会持续带来三个问题：

1. **改动范围过大**：任何 recovery / rollback / BFT / metrics 改动都容易在同一文件互相踩线
2. **测试定位困难**：同一条红测可能横跨 restore、event、block loop 三个责任区
3. **后续架构演进受阻**：lane budget、finality seam、ordering abstraction 很难再往里塞而不继续恶化结构

---

## 2. 现状职责切片（按当前 `main.rs`）

以下行号基于当前 `main.rs` 结构，目的是标出**第一刀可拆 seam**，不是形成永久 ABI。

### A. 配置 / CLI / 基础类型
- `Args` / `WalDirMode` / `NodeConfig`：约 `35-122`
- `MockTx` 与若干 BFT struct：约 `123-377`

### B. WAL / checkpoint / recovery
- `wal_file(...)` 起：约 `378`
- `load_wal_meta_entries(...)` 起：约 `434`
- `recover_wal_state(...)` 起：约 `487`
- `ensure_recoverable_wal_state(...)` 一直到约 `664`

### C. BFT 核心
- `quorum_threshold(...)` 起：约 `671`
- `simulate_bft_round(...)` 起：约 `1012`
- `simulate_bft_height(...)` 起：约 `1313`

### D. config / demo mempool / tx picking
- `load_config(...)`：约 `1434`
- `build_demo_mempool(...)`：约 `1463`
- `pick_txs_with_critical_guard(...)`：约 `1553`

### E. 事件 / treasury delta / metering event suffix
- `emit_event(...)`：约 `1852`
- `emit_timeout_event(...)`：约 `1952`

### F. rollback / restore / apply
- `TxRollbackSnapshot`：约 `2016`
- `capture_rollback_snapshot(...)`：约 `2032`
- `restore_pending_resolve_approval_from_snapshot(...)`：约 `2137`
- `rollback_tx_snapshot(...)`：约 `2189`
- `apply_one(...)`：约 `2231`

### G. timeout / hot objects / scheduling inputs
- `scan_and_apply_timeouts(...)`：约 `2288`
- `summarize_hot_objects(...)`：约 `2369`
- `read_write_decl(...)`：约 `2422`

### H. pre-exec pool / ordering
- `PreExecJob`：约 `2516`
- `pre_execute_group_parallel(...)`：约 `2657`
- `decide_order_for_commit(...)`：约 `2661`

### I. 主 block loop 与 summary
- `main()`：约 `11773` 开始，承担几乎全部 orchestration

### J. tests
- `#[cfg(test)]` 块：约 `2707` 之后开始

---

## 3. 目标文件树（推荐 v1）

```text
crates/trnm-node/src/
  main.rs
  args.rs
  config.rs
  types.rs
  wal.rs
  recovery.rs
  bft/
    mod.rs
    model.rs
    auth.rs
    round.rs
    height.rs
  mempool.rs
  events.rs
  rollback.rs
  apply.rs
  timeout.rs
  hot_objects.rs
  preexec.rs
  ordering.rs
  summary.rs
  demo.rs
  tests/
    mod.rs
```

### 每个文件的职责

#### `main.rs`
只保留：
- CLI 入口
- 高层 wiring
- 调用各模块
- 最终 summary 输出串接

**目标：从 12.6k 行降到 ~300-600 行 orchestration 文件。**

#### `args.rs`
- `Args`
- `WalDirMode`

#### `config.rs`
- `NodeConfig`
- `load_config(...)`

#### `types.rs`
- `MockTx`
- `RoundStep`
- `VoteType`
- `BftVote` / `SignedVote`
- `AuthRejectStats`
- `LeaderHealth`
- `BftJitterControl`
- `BftHeightResult`
- `HotObjectSummary`
- `ConsensusWal`
- `RecoveredWalState`
- `WalMetaList` / `CheckpointMetaList`
- `DaBatch` / `OrderingDecision`
- `RlAdviceContext` / `RlAdvice`

#### `wal.rs`
- `wal_file`
- `wal_dir_has_existing_state`
- `isolated_default_wal_dir`
- `resolve_wal_dir`
- `wal_meta_file`
- `checkpoint_file`
- `load_wal_meta_entries`
- `persist_wal_meta_entries`
- `load_checkpoint_meta`
- `persist_checkpoint_meta`
- `persist_consensus_wal`

#### `recovery.rs`
- `recover_wal_state`
- `metadata_only_recovery_error`
- `ensure_recoverable_wal_state`

#### `bft/model.rs`
- threshold / proposer selection helpers
- vote signatures
- token canonicalization helpers

#### `bft/auth.rs`
- `accept_signed_vote`
- `detect_double_votes`

#### `bft/round.rs`
- `simulate_bft_round`

#### `bft/height.rs`
- `simulate_bft_height`

#### `mempool.rs`
- `build_demo_mempool`
- `requeue_uncommitted_txs`
- `pick_txs_with_critical_guard`
- `is_critical_tx`
- `task_id_of`
- `event_type_of`
- `event_type_for_apply_outcome`

#### `events.rs`
- `now_unix_ms`
- treasury delta / formatter helpers
- `emit_event`
- `emit_timeout_event`
- metering event suffix helpers

#### `rollback.rs`
- `TxRollbackSnapshot`
- `balance_snapshot`
- `capture_rollback_snapshot`
- resolve approval snapshot canonicalization / restore helpers
- `rollback_tx_snapshot`
- `balance_deltas_from_snapshot`

#### `apply.rs`
- `task_ref`
- `actor_of`
- `verified_signer_of`
- `challenger_of`
- `tx_hash_of`
- `status_name`
- `is_high_risk_tx`
- `is_rejected_by_emergency_pause`
- `apply_one`

#### `timeout.rs`
- `scan_and_apply_timeouts`

#### `hot_objects.rs`
- `pseudo_object_id_for_account`
- `summarize_hot_objects`
- `hot_object_top_label_share_ppm`
- `hot_object_tail_share_ppm`
- `missed_proposals_added_since`
- `read_write_decl`

#### `preexec.rs`
- `PreExecJob`
- `PreExecQueueEntry`
- `PreExecPoolState`
- `PreExecPool`
- `pre_execute_group_parallel`

#### `ordering.rs`
- `LegacyMempoolDaProvider`
- `PreexecOrderingEngine`
- RL advisor shadow structs
- `decide_order_for_commit`

#### `summary.rs`
- percentile / avg / share / gap helpers
- 最终 block loop summary 打印辅助

#### `demo.rs`
- `compute_commitment`
- `demo_worker_name`
- 任何只服务 demo load 的辅助函数

#### `tests/mod.rs`
- 第一阶段先不拆细测试；先只把 `#[cfg(test)] mod tests;` 拉出主文件
- 第二阶段再按：
  - `tests/bft.rs`
  - `tests/recovery.rs`
  - `tests/rollback.rs`
  - `tests/apply.rs`
  - `tests/timeouts.rs`
  继续细分

---

## 4. 第一刀怎么下（推荐顺序）

## Step 1：纯搬运、不改签名

### 目标
先把**几乎没有循环依赖**、且最稳定的子域移走：

1. `args.rs`
2. `config.rs`
3. `types.rs`
4. `wal.rs`
5. `recovery.rs`

### 原则
- 函数签名尽量不改
- 只改 `use` 路径
- 不同时改测试语义

### 预期收益
- 立刻把 `main.rs` 去掉 WAL / recovery / config 这块硬块
- 为后续 block loop 解耦创造空间

### Gate
- `cargo test -p trnm-node -q`
- `cargo test --workspace --all-targets`

---

## Step 2：把 BFT 子系统拔出来

### 目标
拆：
- `bft/model.rs`
- `bft/auth.rs`
- `bft/round.rs`
- `bft/height.rs`

### 原则
- 不改 BFT 算法
- 不改 round-change / leader health / auth reject 口径
- 先按“现有函数平移”组织

### 风险点
- BFT structs 和 helper 当前都在同一文件，拆时容易碰到 `use` 循环
- 建议把通用 BFT struct 先统一放到 `bft/model.rs`

### Gate
- `cargo test -p trnm-node -q`
- 如有 fault matrix / bft regression script，一并跑

---

## Step 3：拆 apply / rollback / timeout

### 目标
拆：
- `apply.rs`
- `rollback.rs`
- `timeout.rs`
- `events.rs`

### 原因
这是当前最容易反复出红点的责任区：
- live challenged boundary
- rollback restore semantics
- pending resolve approval snapshot
- emergency pause rejection
- treasury delta / timeout event

### 原则
- 先确保同一责任区代码靠近
- 不要在拆文件同时重写语义
- `rollback.rs` 和 `events.rs` 可以共享一个小型内部 helper 模块，但第一刀先不引抽象层

### Gate
- `cargo test -p trnm-node -q`
- `cargo test -p trnm-state --test m1_pause_resolve_escrow_invariant -q`
- `cargo test -p trnm-pouw --lib -q`

---

## Step 4：拆 preexec / ordering / hot_objects

### 目标
拆：
- `preexec.rs`
- `ordering.rs`
- `hot_objects.rs`
- `summary.rs`

### 原因
这块是以后接：
- lane budget
- QoS
- RL advisor shadow
- ordering / finality seam

最需要留出独立接口的地方。

### 原则
- `decide_order_for_commit(...)` 先保持现签名
- 把 RL advisor / DA provider / preexec pool 这些结构，先收拢到同一逻辑区
- 不在这一刀里引入新策略

### Gate
- `cargo test -p trnm-node -q`
- `cargo test -p trnm-executor -q`
- `cargo test -p trnm-mempool -q`

---

## Step 5：把 tests 从 `main.rs` 拔出来

### 目标
- `#[cfg(test)] mod tests;`
- `src/tests/mod.rs`

### 为什么最后做
因为测试会大量引用内部 helper；如果过早移动 tests，会让前几步搬运难度翻倍。

### 第二阶段再细分
可继续拆：
- `tests/bft.rs`
- `tests/recovery.rs`
- `tests/apply.rs`
- `tests/rollback.rs`
- `tests/timeouts.rs`
- `tests/preexec.rs`

---

## 5. 第一阶段不要做的事

## 5.1 不改协议语义
- 不改 `apply_one(...)` 对 `trnm-pouw` 的调用语义
- 不改 pause / rollback / restore 行为
- 不改事件字段

## 5.2 不引入过度抽象
先别上：
- trait-heavy service graph
- generic runtime context injection
- async 全面重写

第一阶段是：
> **把巨石切开，不是重做 node。**

## 5.3 不同时改 tests 语义
除非拆文件过程中不得不修 import / 路径，不然不要顺手改测试含义。

---

## 6. 当前还缺哪些细节模块

这部分不是“把现有函数搬家”，而是当前 `trnm-node` 真正缺的命名边界。

### A. `finality.rs`
当前 node 有：
- BFT round / commit
- execution
- checkpoint / WAL

但没有一个显式 `finality` 层来区分：
- proposal accepted
- block committed
- state applied
- audit finalized

如果以后要接 Conflux-inspired ordering / finality abstraction，这个模块迟早要补。

### B. `lane_budget.rs`
当前已有：
- `pick_txs_with_critical_guard(...)`

但这还只是启发式。未来如果要做：
- free ingress
- control path reservation
- critical tx starvation guard

就需要单独模块化：
- per-lane budget
- reserved capacity
- reject reason / telemetry

### C. `preflight.rs`
当前 preflight/guard 逻辑散落在：
- `is_high_risk_tx`
- `is_rejected_by_emergency_pause`
- `apply_one`
- rollback 前检查

这值得未来独立出来，形成：
- admission/preflight boundary
- apply boundary
- rollback boundary

### D. `telemetry.rs`
现在 metrics/summary helper 分散在 `main.rs` 多处。未来建议单独模块：
- scheduler metrics
- BFT metrics
- hot object metrics
- treasury delta summary
- finality metrics

---

## 7. 推荐的 PR 拆分

### PR-1
- 新增：`args.rs` `config.rs` `types.rs`
- `main.rs` 只改 import

### PR-2
- 新增：`wal.rs` `recovery.rs`
- 迁移 WAL/checkpoint/recovery

### PR-3
- 新增：`bft/`
- 迁移 BFT structs + round/height 模拟

### PR-4
- 新增：`events.rs` `apply.rs` `rollback.rs` `timeout.rs`
- 迁移执行与恢复责任区

### PR-5
- 新增：`hot_objects.rs` `preexec.rs` `ordering.rs` `summary.rs`
- 收口调度/预执行/指标

### PR-6
- `#[cfg(test)] mod tests;`
- 测试迁移出 `main.rs`

---

## 8. 每一步的最低 gate

每一刀最少跑：

- `cargo test -p trnm-node -q`
- `cargo test --workspace --all-targets`

遇到下列责任区时追加：

### 若动 rollback / restore / pause
- `cargo test -p trnm-state --test m1_pause_resolve_escrow_invariant -q`
- `cargo test -p trnm-state --test state_root_regression -q`

### 若动 apply / resolve / challenge
- `cargo test -p trnm-pouw --lib -q`
- `cargo test -p trnm-pouw --lib --features real-tee-backend -q`

### 若动 preexec / ordering / executor glue
- `cargo test -p trnm-executor -q`
- `cargo test -p trnm-mempool -q`

---

## 9. 第一刀的成功标准

`trnm-node` 第一轮拆分算成功，不是看“文件变多了”，而是看：

1. `main.rs` 从 12k+ 行明显降下来
2. WAL/recovery/BFT/apply/rollback 不再都混在一个文件里
3. 所有原有 gate 仍绿
4. 后续 `lane_budget.rs` / `finality.rs` / `preflight.rs` 有明确落点

---

## 10. 最终建议

如果现在就要开始动代码，建议**按 PR-1 开刀**：

> 先搬 `args.rs` / `config.rs` / `types.rs` / `wal.rs` / `recovery.rs`，不要先碰 apply/rollback/BFT 语义区。

这是风险最低、收益也最高的起手式。

等这一步稳定后，再拆 `bft/` 与 `apply/rollback/timeout`，就不会在一个 12k 单文件里反复滚雪球。
