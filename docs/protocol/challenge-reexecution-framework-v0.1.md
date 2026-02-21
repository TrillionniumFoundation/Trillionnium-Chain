# Challenge Re-Execution Framework v0.1（Lite）

更新日期：2026-02-19

## 目标
在不改变当前链上共识执行复杂度的前提下，建立“挑战后重执行”的最小闭环：
1. 收集可重执行输入（task/challenge/result 元数据）
2. 产出离线重执行结论（`challengeSucceeded` + `finalResultHash`）
3. 通过 authority 路径回写 `resolve-challenge`

## 设计边界
- v0.1 为 **off-chain replay + on-chain decision writeback**。
- 链上不直接执行 Docker 重放，仅记录并消费仲裁结果。
- 与现有 `DisputeResolver` 兼容（无需状态迁移）。

## 最小流程
1. `challenge-result` 触发后，导出任务快照：
   - task_id, worker, challenger, result_hash, result_uri, evidence_uri
2. 离线重执行器根据快照运行并输出：
   - `reexec_outcome` (`match` / `mismatch`)
   - `reexec_result_hash`
   - `report_uri`（可选）
3. 由 authority 调用：
   - `resolve-challenge <task-id> <challenge-succeeded> <final-result-hash> <memo>`

## 判定规则（建议）
- `reexec_outcome = mismatch` → `challengeSucceeded=true`
- `reexec_outcome = match` → `challengeSucceeded=false`
- `final-result-hash` 默认采用 `reexec_result_hash`，为空时回退原 `task.result_hash`

## 观测字段（建议）
resolve memo 推荐包含：
- `reexec_report_uri=`
- `reexec_engine=`
- `reexec_version=`
- `trace_id=`（用于 worker log / chain event / reexec artifact 串联）

当前实现：`resolve-challenge` 事件会从 memo 解析 `trace_id=` 并写入事件属性。

## 一键产物（v0.1 实操）

可直接生成最小仲裁证据包（`decision.json + resolve-template.txt + summary.md`）：

```bash
cd TrillionniumChain
./scripts/challenge_reexec_bundle.sh <task_id> <match|mismatch> [reexec_hash] [orig_hash]
```

输出目录：`data/reexec-bundles/<timestamp>-<task_id>/`

## v0.2 演进方向
- 引入标准化重执行报告 schema（JSON）
- 对 resolver 增加 report digest 校验
- 将 replay 结果接入治理提案模板自动生成
