# PoUW 验证闭环 V1（接口草案）

> 目标：在现有 `x/workload` 基础上，把“提交结果 → 可挑战窗口 → 仲裁结算”跑通，形成最小可用的可验证计算闭环。

## 1) 状态机（Task.status）

建议把当前数字状态明确化（保持 uint64 存储）：

- `0 OPEN`：任务已创建，等待 worker 认领/提交。
- `1 RESULT_SUBMITTED`：worker 已提交结果哈希，进入挑战期。
- `2 COMPLETED`：挑战期结束且无人成功挑战，任务最终确认。
- `3 CHALLENGED`：收到挑战，等待仲裁。
- `4 SLASHED`：仲裁确认 worker 恶意，已惩罚并结案。
- `5 CANCELLED`：可选，异常取消（V1 可不开放）。

> 兼容建议：当前代码里 `2` 被当作 completed，沿用即可，新增 1/3/4。

## 2) 新增消息接口（tx.proto）

```proto
rpc SubmitResult    (MsgSubmitResult   ) returns (MsgSubmitResultResponse);
rpc ChallengeResult (MsgChallengeResult) returns (MsgChallengeResultResponse);
rpc ResolveChallenge(MsgResolveChallenge) returns (MsgResolveChallengeResponse);
```

### 2.1 MsgSubmitResult

```proto
message MsgSubmitResult {
  option (cosmos.msg.v1.signer) = "creator";
  string creator = 1;      // worker address
  uint64 taskId = 2;
  string resultHash = 3;   // deterministic output hash
  string resultUri = 4;    // optional: IPFS CID/URL
}
message MsgSubmitResultResponse {}
```

语义：
- 仅活跃 worker 可提交。
- 仅 `OPEN` 任务可提交。
- 成功后：`status=RESULT_SUBMITTED`，记录 worker、resultHash、challengeDeadlineHeight。

### 2.2 MsgChallengeResult

```proto
message MsgChallengeResult {
  option (cosmos.msg.v1.signer) = "creator";
  string creator = 1;      // challenger
  uint64 taskId = 2;
  string reason = 3;       // optional
  string evidenceUri = 4;  // optional
}
message MsgChallengeResultResponse {}
```

语义：
- 仅在挑战窗口内可发起。
- 需收取挑战保证金（防垃圾挑战）。
- 成功后：`status=CHALLENGED`，记录 challenger 与 challengeId。

### 2.3 MsgResolveChallenge

```proto
message MsgResolveChallenge {
  option (cosmos.msg.v1.signer) = "creator";
  string creator = 1;      // authority only
  uint64 taskId = 2;
  bool challengeSucceeded = 3;
  string finalResultHash = 4; // optional
  string memo = 5;           // optional
}
message MsgResolveChallengeResponse {}
```

语义：
- 仅模块 authority（治理/仲裁）可调用。
- `challengeSucceeded=true`：worker 恶意，执行 slash，状态置 `SLASHED`。
- `challengeSucceeded=false`：挑战失败，罚 challenger 保证金，任务置 `COMPLETED`。

## 3) Task/Challenge 数据结构

## 3.1 Task 扩展字段（task.proto）

```proto
uint64 challengeDeadlineHeight = 8;
string challenger = 9;
uint64 challengeId = 10;
```

## 3.2 新增 Challenge 对象（challenge.proto）

```proto
message Challenge {
  uint64 id = 1;
  uint64 taskId = 2;
  string challenger = 3;
  string worker = 4;
  uint64 status = 5; // 0 open, 1 succeeded, 2 failed
  uint64 deposit = 6;
  string reason = 7;
  string evidenceUri = 8;
  uint64 createdHeight = 9;
  uint64 resolvedHeight = 10;
}
```

## 4) Params（建议新增）

在 `params.proto` 增加：

- `uint64 challenge_window_blocks`
- `uint64 challenge_deposit`
- `uint64 challenger_slash_percent`（或固定金额）
- `uint64 worker_slash_percent_on_bad_result`（上限仍受 50% 约束）

## 5) 结算与资金流

## 5.1 SubmitResult
- 不动赏金 escrow（仍在 module account）。
- 锁定 challenge deadline。

## 5.2 无挑战直通完成（EndBlocker 或显式 finalize）
- 当 `RESULT_SUBMITTED` 且过期无挑战：`status=COMPLETED`。
- 执行任务费处理（你的当前政策为 100% burn，可保持）。

## 5.3 Challenge 成功
- slash worker stake（调用既有 `SlashWorker` 核心逻辑，建议抽公共函数避免重复）。
- challenger 保证金返还（可加奖励）。
- 任务 `SLASHED`。

## 5.4 Challenge 失败
- 惩罚 challenger 保证金（burn 或转模块）。
- worker 结果确认，任务 `COMPLETED`。

## 6) 错误码建议（types/errors.go）

建议追加：

- `ErrTaskInvalidStatusTransition`
- `ErrTaskChallengeWindowExpired`
- `ErrTaskChallengeWindowNotExpired`
- `ErrTaskAlreadyChallenged`
- `ErrChallengeNotFound`
- `ErrUnauthorizedResolver`
- `ErrInvalidResultHash`
- `ErrChallengeDepositTooLow`

## 7) Keeper 伪代码

## 7.1 SubmitResult

```go
func SubmitResult(ctx, msg) {
  task := GetTask(msg.taskId)
  require(task.Status == OPEN)
  require(IsActiveWorker(msg.creator))
  require(validHash(msg.resultHash))

  task.Worker = msg.creator
  task.ResultHash = msg.resultHash
  task.Status = RESULT_SUBMITTED
  task.ChallengeDeadlineHeight = ctx.BlockHeight() + params.ChallengeWindowBlocks
  SetTask(task)

  emit(task_submit_result)
}
```

## 7.2 ChallengeResult

```go
func ChallengeResult(ctx, msg) {
  task := GetTask(msg.taskId)
  require(task.Status == RESULT_SUBMITTED)
  require(ctx.BlockHeight() <= task.ChallengeDeadlineHeight)
  require(task.ChallengeId == 0)

  collectChallengeDeposit(msg.creator)
  ch := NewChallenge(...)
  SetChallenge(ch)

  task.Status = CHALLENGED
  task.Challenger = msg.creator
  task.ChallengeId = ch.Id
  SetTask(task)

  emit(task_challenged)
}
```

## 7.3 ResolveChallenge

```go
func ResolveChallenge(ctx, msg) {
  require(msg.creator == authority)

  task := GetTask(msg.taskId)
  require(task.Status == CHALLENGED)
  ch := GetChallenge(task.ChallengeId)

  if msg.challengeSucceeded {
    slashWorker(task.Worker, params.WorkerSlashPercentOnBadResult)
    refundOrRewardChallenger(ch)
    task.Status = SLASHED
    ch.Status = SUCCEEDED
  } else {
    slashChallengerDeposit(ch)
    finalizeTaskAndBurnEscrow(task)
    task.Status = COMPLETED
    ch.Status = FAILED
  }

  SetChallenge(ch)
  SetTask(task)
  emit(challenge_resolved)
}
```

## 8) 测试最小集（必须）

1. `SubmitResult_SetsDeadlineAndStatus`
2. `ChallengeResult_WithinWindow_Success`
3. `ChallengeResult_AfterWindow_Fails`
4. `ResolveChallenge_Success_SlashesWorker`
5. `ResolveChallenge_Fail_SlashesChallenger`
6. `FinalizeWithoutChallenge_AfterDeadline_Completes`

## 9) 迁移与兼容

- 不破坏已有 `CreateTask`。
- `UpdateTask` 建议逐步废弃，仅保留 admin/debug 路径，避免绕过闭环。
- 先合入 V1 结构与测试，再接 worker 客户端自动提交。

---

## 建议落地顺序（执行顺序）

1. proto 增量：`tx/task/params/challenge.proto`
2. 生成代码 + 编译通过
3. keeper 三个 msg + store challenge
4. 单测 6 个场景
5. smoke 脚本：`create -> submit -> challenge -> resolve`
