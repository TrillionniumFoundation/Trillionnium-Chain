# Rust L1 v1 冻结收口执行清单

日期：2026-02-20  
范围：`trnm-node` / `trnm-pouw` / `trnm-state` / CI 门禁

## A. 协议语义一致性（必须）

- [ ] 状态迁移仅允许：
  `OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED|SLASHED`
- [ ] 非法路径统一返回 `InvalidTransition`
- [ ] 对外错误语义收敛到最小集合：
  `InvalidTransition / VersionConflict / MissingWorker / MissingCommitment / CommitmentMismatch / Unauthorized / InsufficientStake`
- [ ] `resolve` 仅在 `CHALLENGED` 可执行，并能区分 `slash_worker=true|false`

## B. 事件字段冻结（必须）

- [ ] 所有状态迁移事件包含：
  `event_type task_id from_status to_status actor tx_id block_height state_root ts_unix_ms`
- [ ] `resolve` 事件额外包含：
  `slash_worker resolution_code`
- [ ] `event_schema=v1` 出现在事件行中

## C. 自动化门禁（必须）

- [x] 本地脚本：`trillionnium-rust/scripts/run_v1_protocol_gates.sh`
- [x] 事件字段检查：`trillionnium-rust/scripts/check_event_fields.sh`
- [x] 事件回放顺序检查：`trillionnium-rust/scripts/check_event_replay_smoke.sh`
- [x] 并行路径异常检查（`apply_error/rollback`）
- [x] CI `trnm-merge-gates.yml` 接入 Rust L1 v1 protocol gates
- [x] CI 触发路径覆盖 `trillionnium-rust/**`（防止仅文档变更才触发）

## D. 运行命令（统一口径）

```bash
cd trillionnium-rust
./scripts/run_v1_protocol_gates.sh
```

## E. 验收标准（Freeze Ready）

- [ ] 本地 `run_v1_protocol_gates.sh` 通过
- [ ] PR CI（merge gates）通过
- [ ] Nightly health（classic + mixed + state_root audit）通过
- [ ] 任一新增优化 PR 不改变 A/B 两节的协议语义与字段
