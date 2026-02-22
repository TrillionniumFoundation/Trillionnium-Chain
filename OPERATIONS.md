# Operations Manual

## Workload Module

### RequestUnbonding

The `RequestUnbonding` message allows a worker to initiate the process of unstaking their tokens.

#### Business Logic
1.  **Validation**:
    *   Checks if the request is valid (not nil).
    *   Verifies the creator address format.
    *   Checks if the worker exists (`ErrWorkerNotFound`).
    *   **Stake Check**: Verifies that the worker has a non-zero stake. If `Stake == 0`, the request is rejected with `ErrInvalidRequest` ("worker has no stake to unbond").
    *   Checks if an unbonding request already exists for the worker (`ErrUnbondingAlreadyRequested`).
    *   Verifies the block height is within safe bounds.

2.  **Execution**:
    *   Calculates the release height (`CurrentHeight + UnbondingPeriodBlocks`).
    *   Creates an `Unbonding` record with the calculated release height and the worker's current stake.
    *   Removes the `Worker` record immediately (worker exits active set).
    *   Emits a `workload_request_unbonding` event.


### FinalizeUnbonding

The `FinalizeUnbonding` message allows a user to claim their unbonded tokens after the unbonding period has elapsed.

#### Business Logic
1.  **Validation**:
    *   Checks if the request is valid (not nil).
    *   Verifies the creator address format.
    *   Checks if an `Unbonding` record exists for the creator (`ErrUnbondingNotFound`).
    *   Checks if the current block height has reached or exceeded the `ReleaseHeight` (`ErrUnbondingCooldownNotReached`).

2.  **Execution**:
    *   Retrieves the stored `Unbonding` amount.
    *   Transfers the unbonded tokens from the module account back to the user's account (via BankKeeper).
    *   Removes the `Unbonding` record from the store.
    *   Emits a `workload_finalize_unbonding` event.

#### State Consistency
*   **Worker Removal**: The `Worker` record is removed during `RequestUnbonding`. `FinalizeUnbonding` ensures that no "zombie" worker record exists.
*   **Unbonding Cleanup**: The `Unbonding` record is strictly removed upon successful finalization to prevent double spending.

### Test Coverage
*   `x/workload/keeper`: ~92.7%
*   New Test: `TestFinalizeUnbonding_StateConsistency` verifies that:
    1.  Worker record is removed after `RequestUnbonding`.
    2.  Unbonding record is created correctly.
    3.  After `FinalizeUnbonding`, both Worker and Unbonding records are absent.

## Compute Module

### CreateComputeJob

The `CreateComputeJob` message allows a user to submit a compute job which creates a task in the Workload module.

#### Business Logic
1.  **Validation**:
    *   Checks if the payload is empty (`ErrInvalidPayload`).
    *   Verifies the creator address format.

2.  **Execution**:
    *   Creates a `Task` in the Workload module with the provided payload as `IpfsHash`.
    *   Returns the new `JobId` (which corresponds to the Task ID in Workload module).

### Integration Test
*   `TestCreateComputeJob_Integration`:
    *   Verifies that calling `CreateComputeJob` creates a corresponding task in `Workload` module.
    *   Queries the task using the returned `JobId` to confirm side effects.
    *   Validates error handling for empty payload.

## E2E Worker Runbook (Job -> Execute -> Commit)

### Prerequisites
- Local chain is running (`chaind status` returns latest height)
- Docker daemon is running
- Worker config exists at `worker/config.yaml`

### 1) Batch submit jobs (with sequence-mismatch retry)
```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/submit_jobs.sh ./tasks/example_futures cpu 3
```

### 2) One-command end-to-end smoke
```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/e2e_smoke.sh 2
```

The smoke script automatically:
1. checks chain availability
2. ensures a single worker instance
3. submits N jobs
4. waits for processing
5. verifies `result committed on-chain` appears N times in `worker/worker.log`

### 3) Pass criteria
- script exits with code `0`
- terminal prints `SMOKE PASS ✅`
- worker log contains entries like:
  - `Submitting MsgCompleteJob for Job <id>...`
  - `✅ Job <id> result committed on-chain`

## Rust Worker Receipt Gate（唯一入口）

在仓库根目录执行：

```bash
./scripts/v2/run_worker_receipt_gates.sh
```

说明：
- 这是 worker 回执门禁的唯一入口命令（与 CI / relay 一致）。
- 内部包含：
  1. `worker_agent_full_loop.sh`
  2. `worker_replay_guard_test.sh`
  3. `worker_failed_receipt_test.sh`
  4. `worker_resume_no_duplicate_test.sh`

真实 CLI 就绪度检查（接入前建议先跑）：

```bash
./scripts/v2/worker_real_cli_readiness.sh
# 强制模式：未就绪则直接非 0 退出
REQUIRE_REAL_TX_CLI=1 ./scripts/v2/worker_real_cli_readiness.sh
```

真实 CLI 全量门禁（readiness + receipt gates 一键）：

```bash
TRNM_TX_CLI=<your-real-tx-cli> ./scripts/v2/run_worker_receipt_gates_real_cli.sh
# 本地最小示例（wrapper）
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_wrapper.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh
# Rust-native CLI（先 build）
TRNM_TX_CLI=./trillionnium-rust/target/debug/trnm-cli ./scripts/v2/run_worker_receipt_gates_real_cli.sh
# 真实链适配器（按环境变量配置真实 tx 命令）
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_real_adapter.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

推荐先用环境模板：

```bash
cp scripts/v2/worker_real_cli.env.example /tmp/worker_real_cli.env
# 编辑 /tmp/worker_real_cli.env 中的 TRNM_TX_COMMIT_CMD / TRNM_TX_REVEAL_CMD
source /tmp/worker_real_cli.env
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_real_adapter.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

真实适配模板与规范：
- 规范：`docs/protocol/worker-real-tx-cli-adapter-spec.md`
- 模板：`scripts/v2/trnm_tx_cli_real_adapter.template.sh`

## Agent↔User P2P Phase A（MVP）

文档入口：`docs/protocol/agent-user-p2p-phaseA-ops.md`

补充运维文档（ack 批量 / retry 熔断参数与排障）：`docs/OPERATIONS.md`

最小门禁命令：

```bash
cd trillionnium-rust
./scripts/run_agent_user_phasea_gate.sh
```

可选：启用持久化 reliability store（sqlite smoke）

```bash
cd trillionnium-rust
RELIABILITY_STORE=sqlite \
RELIABILITY_DB_PATH=run/health/reliability-phasea.sqlite \
./scripts/run_agent_user_phasea_gate.sh
```

一键串联门禁（失败即停，先共识安全矩阵，再 proof 检查，再 Phase A）：

```bash
cd trillionnium-rust
./scripts/run_phasea_security_oneshot.sh
# 可选：自定义产物根目录
# RUN_ROOT=/tmp/trnm-gate-oneshot ./scripts/run_phasea_security_oneshot.sh
```

结果解读（one-shot）：
- 第一步（共识安全矩阵）摘要：`<RUN_ROOT>/consensus-security/summary.txt`
  - `result=PASS`：矩阵全通过
  - `result=FAIL`：至少一个子项失败（查看同目录 `*.log`）
- 第二步（proof smoke + tamper）日志：`<RUN_ROOT>/proof-gate.log`
  - 用例：`relay_session_proof_smoke_and_tamper_matrix`
  - 覆盖：缺片段 / 顺序错乱 / 内容篡改 / root 不匹配
- 第三步（Phase A）报告目录：`<RUN_ROOT>/agent-user-phasea/`
  - 报告文件：`agent-user-phasea-gate-<ts>.txt`
  - 关键字段应包含：`status=COMMIT_QUEUED`、`verifier_status=accepted`、`status=PASS`

门禁断言：
- `trnm-rpc` 与 `trnm-worker-agent` 构建测试通过
- relay proof smoke + tamper 用例通过（缺片段/顺序错乱/内容篡改/root 不匹配）
- submit/dispatch/consume/query 最小闭环通过
- `query-request-full` 满足：`status=COMMIT_QUEUED` 且 `verifier_status=accepted`

