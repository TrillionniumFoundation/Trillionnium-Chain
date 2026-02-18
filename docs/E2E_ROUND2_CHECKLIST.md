# TrillionniumChain Round-2 联调清单（Create → Execute → Complete）

## 目标（Definition of Done）
完成一条最小闭环并可重复：
1. 创建 Compute Job 成功（链上生成 Job + Workload Task）
2. 合格 Worker 请求执行成功（状态 `CREATED -> RUNNING`）
3. Worker 完成任务成功（状态 `RUNNING -> COMPLETED`）
4. Workload Task 同步完成（`status=2`，写入 `worker/result_hash`）
5. 全量测试 `go test ./...` 通过

## 当前已完成（本轮代码）
- 新增 `workload.Keeper.CompleteTask(...)`：
  - 复用任务完成结算策略（按 bounty 执行 burn；bounty=0 时跳过）
  - 持久化 `status/worker/result_hash`
  - 发出 `workload_update_task` 事件
- 新增 `compute.MsgCompleteJob` 服务实现：
  - 校验 job 存在、状态为 RUNNING、且由 assigned worker 提交
  - 调用 `workloadKeeper.CompleteTask`
  - 将 Job 置为 `COMPLETED`
- 新增集成测试 `TestCompleteJob_Integration`
- 已验证 `chain/` 下 `go test ./...` 通过

## 下一轮（无需确认，建议直接推进）
1. **CLI/E2E 烟测脚本化** ✅
   - 已在 `chain/tools/` 增加 `compute_lifecycle_smoke.sh`
   - 支持输出结构化 `SUMMARY_JSON=1`
2. **失败路径覆盖**
   - 非 assigned worker 完成任务
   - 非 RUNNING 状态重复完成
   - 不存在 job_id
3. **观测性增强**
   - 在 `CompleteJob` 添加事件（job_id, task_id, worker, status）
4. **经济参数联动回归**
   - bounty>0 情况下验证 burn 事件中的 denom 与 params 一致

## 快速验证命令
```bash
cd chain
go test ./x/workload/keeper ./x/compute/keeper
go test ./...
```
