# Rust L1 v1 Interface Freeze (PoUW Core)

状态：Draft-Freeze-Candidate  
日期：2026-02-19  
适用范围：`trillionnium-rust` 主线（`trnm-pouw` / `trnm-node` / `trnm-types`）

## 1. 目标

冻结 v1 核心闭环接口，避免后续性能迭代引入协议层反复改动。  
冻结对象：

- 状态机迁移语义
- 交易输入/输出字段（逻辑层）
- 错误码分层
- 事件字段（可观测/审计）

> 备注：执行器策略（Original / AggressiveGreedy）不属于协议接口，属于实现层策略。

---

## 2. 状态机冻结

状态集合（冻结）：

`OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED | SLASHED`

允许迁移（v1 冻结）：

1. `create_task`：`(none) -> OPEN`
2. `accept_task`：`OPEN -> ASSIGNED`
3. `commit_result`：`ASSIGNED -> COMMITTED`
4. `reveal_result`：`COMMITTED -> REVEALED`
5. `challenge`：`REVEALED -> CHALLENGED`
6. `resolve(slash=false)`：`CHALLENGED -> COMPLETED`
7. `resolve(slash=true)`：`CHALLENGED -> SLASHED`

禁止迁移：其余全部路径（返回 `InvalidTransition`）。

---

## 3. 核心接口（逻辑层）

以下为协议语义字段，具体 CLI/RPC 可包装，但不可改变字段含义。

### 3.1 create_task

输入：

- `task_id: u64`
- `creator: string`
- `bounty: u128`

输出：

- `task_ref: ObjectRef(id, version)`
- `status: OPEN`

### 3.2 accept_task

输入：

- `task_ref: ObjectRef`
- `worker: string`

输出：

- `status: ASSIGNED`

### 3.3 commit_result

输入：

- `task_ref: ObjectRef`
- `worker: string`
- `committed_hash: Hash32`

输出：

- `status: COMMITTED`

### 3.4 reveal_result

输入：

- `task_ref: ObjectRef`
- `worker: string`
- `result_hash: Hash32`
- `reveal_salt: [u8; 32]`

校验：

`sha256("{task_id}|{hex(result_hash)}|{hex(reveal_salt)}|{worker}") == committed_hash`

输出：

- `status: REVEALED`

### 3.5 challenge

输入：

- `task_ref: ObjectRef`
- `challenger: string`
- `reason_code: string`（v1 仅审计用途，不影响状态机分支）

输出：

- `status: CHALLENGED`

### 3.6 resolve

输入：

- `task_ref: ObjectRef`
- `authority: string`
- `slash_worker: bool`

输出：

- `status: COMPLETED | SLASHED`

---

## 4. 错误码冻结（最小集合）

v1 要求所有实现映射到以下稳定错误语义：

- `InvalidTransition`
- `VersionConflict`
- `MissingWorker`
- `MissingCommitment`
- `CommitmentMismatch`
- `Unauthorized`
- `InsufficientStake`（challenge/worker stake 相关）

实现可有内部细分错误，但对外需稳定映射上述集合。

---

## 5. 事件字段冻结（审计最小集）

每个状态迁移事件至少包含：

- `event_type`（create/accept/commit/reveal/challenge/resolve）
- `task_id`
- `from_status`
- `to_status`
- `actor`
- `tx_id`
- `block_height`
- `state_root`
- `ts_unix_ms`

`resolve` 事件额外包含：

- `slash_worker`
- `resolution_code`

---

## 6. 兼容性与变更策略

- v1 内：禁止 breaking change。
- 新增字段：仅允许“可选字段 + 默认值”方式。
- 删除字段/重命名：必须走 v2 升级提案。
- `AggressiveGreedy` 等执行策略实验：不得改变第 2~5 节语义。

---

## 7. 验收门槛（冻结生效条件）

冻结生效需同时满足：

1. `cargo test --workspace` 通过。
2. P1 negative suite 全绿（`pass=6 fail=0 skip=0`）。
3. Nightly gate 全绿（含 executor spot-check regression gate）。
4. 本文件与实现对齐（抽样 2 条路径：happy path + forged reveal）。

---

## 8. 下一步实现任务（直接可执行）

1. 在 `trnm-pouw` 中将错误映射统一收敛到第 4 节集合。
2. 在 `trnm-node` 日志/事件输出中补齐第 5 节字段。
3. 在 CI 增加“接口冻结一致性检查”（检查必须事件字段存在）。
