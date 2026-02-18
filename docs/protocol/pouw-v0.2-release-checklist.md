# PoUW v0.2 Release Checklist

> 用于测试网前/发布前最终核对。

## A. Build & Test

- [ ] `go test ./... -count=1` 通过
- [ ] `go test ./x/workload/... -count=1` 通过
- [ ] `make smoke-pouw-e2e` 通过
- [ ] `./tools/smoke_pouw_cli_flow.sh` 通过

## B. Core Flow

- [ ] `create-task` 成功并产生 `bounty_lock`
- [ ] `accept-task` 成功，任务 `OPEN -> ASSIGNED`
- [ ] `commit-result` 成功（仅 assigned worker）
- [ ] `reveal-result` 成功，进入 `RESULT_SUBMITTED`
- [ ] `challenge-result` 成功，进入 `CHALLENGED`
- [ ] `resolve-challenge(true)` -> `SLASHED`
- [ ] `resolve-challenge(false)` -> `COMPLETED`
- [ ] challenge window 到期自动 finalize 生效
- [ ] reveal window 到期自动回收 commit 生效

## C. Security & Authority

- [ ] 非 authority 调用 `resolve-challenge` 被拒绝
- [ ] 非 assigned worker 的 commit/reveal 被拒绝
- [ ] 非注册 worker 的 `accept-task` 被拒绝
- [ ] 状态非法迁移被拒绝（`ErrInvalidTaskStateTransition`）

## D. Economics & Fund Flow Events

- [ ] 事件 `workload_fund_flow` 字段完整（task_id/from/to/amount/denom/reason）
- [ ] `bounty_lock` 可观测
- [ ] `challenge_deposit` 可观测
- [ ] `challenge_burn` 可观测
- [ ] `challenge_refund` 可观测
- [ ] `worker_slash` 可观测
- [ ] `task_burn` 可观测

## E. Compatibility

- [ ] `allow_legacy_submit_result=true` 时 legacy 提交可用
- [ ] `allow_legacy_submit_result=false` 时 legacy 提交被拒绝
- [ ] 文档与链上行为一致

## F. Go / No-Go

Only GO when:
1. A/B/C/D 全部勾选
2. 至少 1 次完整 CLI 流程日志归档
3. 至少 1 名独立同事复现通过
