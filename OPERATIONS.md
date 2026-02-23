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

## 产品层最小 API 联调（Create Account -> Balance -> Transfer -> GetTx）

> 目标：用一套可脚本化步骤，验证产品层最小交易闭环。

### 前置
- RPC endpoint 可用（默认 `http://127.0.0.1:8545`）
- 测试账户已注资（本地 dev/faucet 均可）

### 1) 创建账户（示例）

```bash
# 示例：本地生成一对测试地址；也可替换为你现有的钱包地址
ALICE_ADDR=${ALICE_ADDR:-trnm1alice...}
BOB_ADDR=${BOB_ADDR:-trnm1bob...}
RPC_URL=${RPC_URL:-http://127.0.0.1:8545}
```

### 2) 查询余额（balance）

```bash
curl -sS "$RPC_URL" -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":1,
  \"method\":\"balance\",
  \"params\":{\"address\":\"$ALICE_ADDR\"}
}"
```

### 3) 转账（nonce + sendTx）

```bash
# 先取 nonce
NONCE=$(curl -sS "$RPC_URL" -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":2,
  \"method\":\"nonce\",
  \"params\":{\"address\":\"$ALICE_ADDR\"}
}" | jq -r '.result.nonce')

# 发交易（signature 按你的 signer/钱包实现替换）
TX_HASH=$(curl -sS "$RPC_URL" -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":3,
  \"method\":\"sendTx\",
  \"params\":{
    \"from\":\"$ALICE_ADDR\",
    \"to\":\"$BOB_ADDR\",
    \"amount\":\"1000000\",
    \"denom\":\"utrnm\",
    \"nonce\":$NONCE,
    \"signature\":\"0x...\"
  }
}" | jq -r '.result.txHash')

echo "tx_hash=$TX_HASH"
```

### 4) 查询交易（getTx）

```bash
curl -sS "$RPC_URL" -H 'content-type: application/json' -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":4,
  \"method\":\"getTx\",
  \"params\":{\"txHash\":\"$TX_HASH\"}
}"
```

### 通过标准
- `balance` 返回账户与 `utrnm` 余额字段
- `nonce` 返回可用 nonce 且为非负整数
- `sendTx` 返回 `txHash`
- `getTx` 最终状态为 `committed` / `success`（以实现返回字段为准）

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

默认：启用 sqlite 持久化 reliability store（可用 `RELIABILITY_STORE=memory` 显式切回内存模式）

```bash
cd trillionnium-rust
# 可覆盖默认 DB 路径
RELIABILITY_DB_PATH=run/health/reliability-phasea.sqlite \
./scripts/run_agent_user_phasea_gate.sh
```

### 2h Soak 压测 Harness（submit/dispatch/worker/query 持续闭环）

从仓库根目录执行（默认 2 小时）：

```bash
./scripts/v2/run_reliability_soak.sh
```

快速 smoke（例如 5 分钟）：

```bash
./scripts/v2/run_reliability_soak.sh --duration 5m --clean
```

产物（可审计）：
- `run/health/reliability-soak-<ts>.json`：完整指标与参数
- `run/health/reliability-soak-<ts>.txt`：人类可读摘要
- `run/health/reliability-soak-<ts>.audit.jsonl`：逐周期事件审计轨迹

默认行为：
- `RELIABILITY_STORE=sqlite`（未显式设置时）
- 持续执行 submit → dispatch-open → run-assigned → flush-submissions → query-request-full
- 汇总吞吐（submit/terminal TPS）与成功率（提交成功率、终态成功率）

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

### Phase A 一键回滚（commit/tag）

从仓库根目录执行：

```bash
./scripts/rollback_phasea.sh <commit-or-tag>
# 跳过交互确认
./scripts/rollback_phasea.sh <commit-or-tag> --yes
```

脚本行为（失败即退出）：
1. 校验目标 commit/tag 可解析
2. 安全确认（默认要求输入 `ROLLBACK`）
3. 切换到目标版本（`git checkout --detach`）
4. 清理运行态（devnet_down + 常见本地进程 + 临时文件）
5. 执行最小验证：`trillionnium-rust/scripts/run_agent_user_phasea_gate.sh`

安全防护：
- 默认要求工作区干净；如确需覆盖可显式设置 `ALLOW_DIRTY=1`
- 失败会打印日志路径，默认输出到：
  - `run/rollback-phasea/<timestamp>/rollback.log`
  - `run/rollback-phasea/<timestamp>/agent-user-phasea/`

