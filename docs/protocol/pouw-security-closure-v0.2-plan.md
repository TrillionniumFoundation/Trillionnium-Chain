# PoUW 安全闭环 v0.2（文件级改动清单）

> 目标：在现有 `SubmitResult / ChallengeResult / ResolveChallenge` 基础上，补齐 commit-reveal、严格状态机、超时与最小可替换仲裁接口，形成“可惩罚”的最小闭环。

---

## 0) 当前基线（已存在）

已具备：
- 任务提交结果：`MsgSubmitResult`
- 结果挑战：`MsgChallengeResult`
- 权威裁决：`MsgResolveChallenge`
- 挑战保证金与失败惩罚逻辑
- 自动 finalize（挑战窗过期后）

问题：
- 缺少 commit-reveal，结果易被抢跑或抄袭
- 状态码分散在 keeper 常量与“裸数字”里（`4 // SLASHED`）
- 缺少 assignment/accept 路径，`SubmitResult` 对 worker 绑定不严格
- 仲裁实现与消息处理耦合，后续替换困难

---

## 1) 任务状态机收敛（强烈建议先做）

### 1.1 修改文件
- `chain/proto/chain/workload/task.proto`
- `chain/x/workload/types/types.go`
- `chain/x/workload/keeper/msg_server_pouw.go`
- `chain/x/workload/keeper/task_completion.go`
- `chain/x/workload/keeper/task_auto_finalize.go`
- `chain/x/workload/types/errors.go`

### 1.2 改动点
1. 在 `task.proto` 新增明确状态（enum 或常量字段约定）：
   - `TASK_OPEN = 0`
   - `TASK_ASSIGNED = 1`
   - `TASK_COMMITTED = 2`
   - `TASK_REVEALED = 3`
   - `TASK_CHALLENGED = 4`
   - `TASK_FINALIZED = 5`
   - `TASK_SLAHSED = 6`（兼容旧拼写后再修；推荐 `TASK_SLASHED`）

2. 在 `types` 集中导出状态常量，禁止 keeper 内裸数字。

3. `SubmitResult` 改为 `RevealResult` 语义（见第 2 节），旧 `SubmitResult` 标注 deprecated（短期兼容）。

4. `task_completion.go` 内 `val.Status = 2` 改为 `TASK_FINALIZED`。

5. `task_auto_finalize.go` 仅处理 `TASK_REVEALED` 且 challenge window 过期的任务。

6. `errors.go` 增加：
   - `ErrInvalidTaskStateTransition`
   - `ErrWorkerMismatch`
   - `ErrChallengeWindowNotStarted`
   - `ErrChallengeWindowExpired`

---

## 2) 引入 Commit-Reveal（核心）

### 2.1 Proto 层

#### 修改文件
- `chain/proto/chain/workload/task.proto`
- `chain/proto/chain/workload/tx.proto`
- `chain/proto/chain/workload/params.proto`

#### 新增字段（task.proto）
- `string commit_hash`（worker 承诺哈希）
- `uint64 commit_height`
- `uint64 reveal_deadline_height`
- `string result_uri`（结果地址，当前在 msg 中有，建议落表）
- `string reveal_salt_hash`（可选；若要保存披露盐的哈希）

#### 新增消息（tx.proto）
- `MsgCommitResult { creator, task_id, commit_hash }`
- `MsgCommitResultResponse {}`
- `MsgRevealResult { creator, task_id, result_hash, result_uri, reveal_salt }`
- `MsgRevealResultResponse {}`

> 兼容策略：保留 `MsgSubmitResult`，但内部路由到 `RevealResult` 或直接拒绝（由参数控制）。

#### 新增参数（params.proto）
- `uint64 reveal_window_blocks`
- `bool allow_legacy_submit_result`

### 2.2 Keeper 层

#### 新增文件
- `chain/x/workload/keeper/msg_server_commit_reveal.go`

#### 修改文件
- `chain/x/workload/keeper/msg_server.go`（注册新 Msg）
- `chain/x/workload/keeper/msg_server_pouw.go`（旧逻辑兼容/迁移）

#### 规则
- `CommitResult`:
  - 仅任务指定 worker 可提交（若尚无 assignment，需先 assignment）
  - 状态 `ASSIGNED -> COMMITTED`
  - 记录 `commit_hash / commit_height / reveal_deadline`

- `RevealResult`:
  - 校验 `hash(task_id, result_hash, reveal_salt, worker)` 与 `commit_hash` 一致
  - 状态 `COMMITTED -> REVEALED`
  - 写入 `result_hash / result_uri / challenge_deadline`

- 超时：
  - `COMMITTED` 且超过 reveal 窗口未 reveal：可触发任务回收/惩罚（v0.2 可先回到 `OPEN` 并清除 worker 绑定）

---

## 3) Worker 绑定与接单流程

### 3.1 文件
- `chain/proto/chain/workload/tx.proto`
- `chain/x/workload/keeper/msg_server_task.go`
- `chain/x/workload/keeper/msg_server_pouw.go`
- `chain/x/workload/types/messages_task.go`

### 3.2 新增消息（建议）
- `MsgAcceptTask { creator, task_id }`

### 3.3 规则
- `CreateTask` 后默认 `OPEN`
- 由已注册 worker `AcceptTask`：`OPEN -> ASSIGNED`
- 仅已绑定 worker 才能 commit/reveal

---

## 4) 挑战/裁决解耦（最小可替换）

### 4.1 文件
- `chain/x/workload/types/expected_keepers.go`
- `chain/x/workload/keeper/keeper.go`
- `chain/x/workload/keeper/msg_server_pouw.go`

### 4.2 改动点
新增仲裁接口（先本地实现）：

```go
type DisputeResolver interface {
    Resolve(ctx context.Context, task types.Task, challenge types.Challenge, req ResolveInput) (ResolveOutput, error)
}
```

- 默认实现：`AuthorityResolver`（沿用当前 authority 判定）
- 后续可替换：重执行验证器 / 证明验证器

---

## 5) 资金流审计事件（防黑箱）

### 文件
- `chain/x/workload/keeper/msg_server_pouw.go`
- `chain/x/workload/keeper/msg_server_slash_worker.go`
- `chain/x/workload/keeper/task_completion.go`

### 要求
每次资金转移都打统一事件：
- `workload_fund_flow`
  - `task_id`
  - `from`
  - `to`
  - `amount`
  - `denom`
  - `reason` (`bounty_lock|challenge_deposit|challenge_refund|challenge_burn|worker_slash|task_burn`)

---

## 6) 测试补齐（必须）

### 新增测试文件
- `chain/x/workload/keeper/msg_server_commit_reveal_test.go`
- `chain/x/workload/keeper/task_state_machine_test.go`
- `chain/x/workload/keeper/task_timeout_recovery_test.go`

### 补充测试场景
1. 正常路径：`OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> FINALIZED`
2. reveal 哈希不匹配（拒绝）
3. 非绑定 worker commit/reveal（拒绝）
4. challenge 成功（worker slash + challenger refund）
5. challenge 失败（challenger 部分 burn）
6. reveal 超时（任务回收策略生效）
7. 旧 `SubmitResult` 兼容开关行为

---

## 7) 迁移与兼容

### 文件
- `chain/x/workload/module/genesis.go`
- `chain/x/workload/types/genesis.go`
- `chain/x/workload/types/params.go`

### 内容
- 为新增 params 给默认值
- 旧 task 无 `commit_hash` 时，允许从 `REVEALED` 兼容过渡（一次性迁移）
- 提供一次链升级脚本说明（如果已出测试网）

---

## 8) 建议实施顺序（可直接开工）

1. **状态常量收敛 + 去裸数字**
2. **proto 增量（commit/reveal + params）并 regenerate**
3. **keeper commit/reveal 实现**
4. **task auto-finalize 与超时处理**
5. **挑战裁决解耦接口**
6. **测试补齐**
7. **文档更新**（`docs/protocol/execution-spec-v0.1.md`）

---

## 9) 非目标（v0.2 暂不做）

- zk 证明上链
- 去中心化仲裁网络
- 跨链结算
- 复杂信誉系统

先把“恶意可罚 + 诚实可结算 + 流程可审计”做硬。

---

## 10) 快速验收标准（Done Definition）

- [ ] 任意任务状态转移都受限且可测试复现
- [ ] commit/reveal 路径可跑通，旧 submit 行为可控
- [ ] 挑战窗、保证金、惩罚逻辑与事件一致
- [ ] 自动 finalize 仅对已 reveal 且未挑战任务生效
- [ ] 单元/集成测试覆盖关键分叉路径
- [ ] 文档与链上行为一致
