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

