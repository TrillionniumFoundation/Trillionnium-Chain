# PoUW V1 Interface Freeze（2026-02-19）

> 本文为 **冻结基线**。实现、CLI、运维脚本、外部集成均以此为准。

## 1) Canonical Task 状态机（冻结）

数值与语义：

- `0 OPEN`
- `1 ASSIGNED`
- `2 COMMITTED`
- `3 REVEALED`
- `4 CHALLENGED`
- `5 COMPLETED`
- `6 SLASHED`

兼容别名：
- `RESULT_SUBMITTED` 仅作为源码兼容别名，映射到 `REVEALED`。

## 2) Canonical 结算路径（冻结）

主路径：
`create-task -> accept-task -> commit-result -> reveal-result -> (optional challenge-result) -> resolve-challenge | auto-finalize`

说明：
- `challenge-result` 仅在 challenge window 内可发起。
- 无挑战且窗口到期时，由 EndBlock 自动 finalize。
- `resolve-challenge` 仅 authority 可调用。

## 3) CLI 合约（冻结）

### 3.1 必须保留（生产路径）
- `accept-task [task-id]`
- `commit-result [task-id] [commit-hash]`
- `reveal-result [task-id] [result-hash] [result-uri] [reveal-salt]`
- `challenge-result [task-id] [reason] [evidence-uri]`
- `resolve-challenge [task-id] [challenge-succeeded] [final-result-hash] [memo]`

### 3.2 兼容保留（非推荐）
- `submit-result [task-id] [result-hash] [result-uri]`
  - 标注为 legacy，仅用于兼容旧集成。

### 3.3 弃用路径
- `update-task`：仅兼容/调试场景，禁止用于生产结算流。

## 4) 权限边界（冻结）

- `resolve-challenge`：authority-only。
- commit/reveal：仅任务绑定 worker。
- challenge：任何满足参数约束的挑战者可发起（需保证金）。

## 5) 事件字段（冻结最小集）

- 任务生命周期事件必须可还原：task_id、from_status、to_status、actor。
- 资金流事件：`workload_fund_flow`，至少包含：
  - `task_id`
  - `from`
  - `to`
  - `amount`
  - `denom`
  - `reason`

推荐 reason 集：
- `bounty_lock`
- `challenge_deposit`
- `challenge_refund`
- `challenge_burn`
- `worker_slash`
- `task_burn`

## 6) 参数基线（冻结）

- `workload_denom = utrnm`
- `challenge_window_blocks = 100`
- `challenge_deposit = 1000000`
- `challenger_slash_percent = 10`
- `worker_slash_percent_on_bad_result = 20`

## 7) DoD（接口冻结完成判据）

- CLI help 与本文一致（命令存在、语义一致）。
- `OPERATOR_CHECKLIST_POUW_V1.md` 与本文一致。
- `RELEASE_NOTES_POUW_V1.md` 与本文一致。
- 旧路径（submit/update）均有明确“legacy/deprecated”标记。
