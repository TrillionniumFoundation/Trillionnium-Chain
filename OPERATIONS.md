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

### 一键 smoke（推荐）

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/v2/product_layer_smoke.sh
```

标准输出会打印清晰的 PASS/FAIL 以及关键字段：
- `address`
- `tx_hash`
- `status`

可选环境变量：
- `CLI_BIN`（默认 `cargo run -q -p trnm-cli --`）
- `WALLET_STORE` / `RUN_DIR`
- `ALICE_NAME` / `BOB_NAME`
- `TRANSFER_AMOUNT` / `DENOM`

### 通过标准
- `wallet create` 成功并产出 `address`
- `query balance` 成功返回 `address/balance`
- `tx transfer` 成功返回 `tx_hash`
- `getTx` 返回 `status`
- 脚本结尾输出 `[SMOKE][PASS] product-layer smoke`

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

### PR-1 安全补丁配套门禁（Tests-Docs）

在仓库根目录执行：

```bash
./scripts/v2/rpc_query_hardcap_enforcement_test.sh
./scripts/v2/governance_value_schema_reject_test.sh
./scripts/v2/worker_real_cli_fake_wrapper_block_test.sh
```

门禁说明：
- `rpc_query_hardcap_enforcement_test.sh`：验证 RPC 查询 hard cap 的 clamp 逻辑（超限被截断、0 回落默认值）。
- `governance_value_schema_reject_test.sh`：验证治理参数 value schema（非法 u64 / 非严格 bool）会被拒绝。
- `worker_real_cli_fake_wrapper_block_test.sh`：验证 fake wrapper 在 strict real-cli gate 下会被拦截（必须非 0 退出）。

建议将以上三项与 `run_worker_receipt_gates_real_cli.sh` 组合为 PR-1 最小验收集。

### PR-2 安全补丁配套门禁（Timeout + Challenge Bond）

在仓库根目录执行：

```bash
./scripts/v2/pouw_commit_timeout_migration_test.sh
./scripts/v2/pouw_challenge_timeout_migration_test.sh
./scripts/v2/challenge_bond_enforcement_test.sh
```

门禁说明：
- `pouw_commit_timeout_migration_test.sh`：扫描并执行 `commit -> timeout` 迁移相关测试（关键词：`commit + timeout + migration`）。
- `pouw_challenge_timeout_migration_test.sh`：扫描并执行 `challenge -> timeout` 迁移相关测试（关键词：`challenge + timeout + migration`）。
- `challenge_bond_enforcement_test.sh`：扫描并执行 challenge bond 强制校验相关测试（关键词：`challenge + bond + enforce/min`）。

验收清单（PR-2）：
- [ ] 三个脚本均成功退出（exit code = 0）
- [ ] 输出中至少命中并执行了目标测试（不是 0 tests）
- [ ] commit 阶段超时迁移路径覆盖
- [ ] challenge 阶段超时迁移路径覆盖
- [ ] challenge 最小 bond / bond enforcement 拒绝路径覆盖

> 说明：脚本会先从 `cargo test -- --list` 中按关键词发现测试；若未发现对应测试，会直接 `FAIL`，用于防止“脚本通过但用例缺失”的假阳性。

### PR-4 门禁（罚没资金流向 + 审计字段可见）

在仓库根目录执行：

```bash
./scripts/v2/pr4_challenge_fundflow_audit_gate.sh
```

门禁说明：
- `bond_forfeiture_flow_test`：验证 challenge 失败后 bond 罚没路径（`challenge_bond_forfeited=true`）。
- `bond_refund_flow_test`：验证 challenge 成功且 worker 被 slash 时 challenger bond 返还路径（`challenge_bond_forfeited=false`）。
- `event_audit_fields_visibility`：验证 resolve 事件审计字段可见（至少包含 `signer/challenger/tx_hash/slash_worker/resolution_code`）。

产物目录：
- 默认写入 `run/pr4-gates/<timestamp>/`（UTC 时间戳）
- 汇总文件：`summary.txt`（包含 `generated_at_utc`）
- 各步骤日志：`bond_forfeiture_flow_test.log` / `bond_refund_flow_test.log` / `event_audit_fields_visibility.log`

验收 checklist（PR-4）：
- [ ] 脚本退出码为 0
- [ ] `summary.txt` 中 `status=PASS`
- [ ] 罚没路径测试通过（forfeiture）
- [ ] 返还路径测试通过（refund）
- [ ] resolve 事件包含 `signer/challenger/tx_hash/slash_worker/resolution_code`

### PR-5 运维查询与对账（Challenge Treasury / Forfeits）

#### A) 快速查询（按 task）

在 `trillionnium-rust/` 下执行：

```bash
# 查询单 task 的事件轨迹（含 challenge/resolve 审计字段）
cargo run -q -p trnm-rpc -- query-events --task-id <TASK_ID> --limit 100
```

重点字段：
- `event_type`（`challenge` / `resolve`）
- `treasury_delta`
- `challenger_delta`
- `bond_disposition`（`posted/forfeited/refunded`）
- `resolution_code`

#### B) 每日对账（日志聚合）

在仓库根目录执行：

```bash
./scripts/v2/pr5_treasury_reconcile_report.sh
```

脚本会自动选择事件日志源（优先 `trillionnium-rust/run/event-field-check.log`），并输出：
- `run/pr5-reconcile/<timestamp>/summary.txt`
- `run/pr5-reconcile/<timestamp>/reconcile.json`

可选参数：
- `SOURCE_LOG=<path>`：强制指定日志输入
- `OUT_DIR=<path>`：指定输出目录

#### C) PR-5 验收 checklist

- [ ] `query-events` 可查到 `challenge/resolve` 事件
- [ ] 事件中可见 `treasury_delta/challenger_delta/bond_disposition`
- [ ] `pr5_treasury_reconcile_report.sh` 成功输出 `summary.txt`
- [ ] `summary.txt` 中 `status=PASS`

更多操作细节：`docs/runbooks/pr5-challenge-treasury-reconcile.md`

## PR-6 Alert Rules（Challenge Treasury 异常告警）

执行：

```bash
./scripts/v2/pr6_alert_rules_gate.sh
```

默认输出：
- `run/pr6-alerts/<timestamp>/summary.txt`（UTC 时间戳目录）
- 机器可解析字段：`status=PASS|WARN|FAIL` + `rule.*`

阈值参数（环境变量）：
- `FAIL_UNRESOLVED_CHALLENGES` / `WARN_UNRESOLVED_CHALLENGES`
- `FAIL_FORFEITS_DAILY_INCREASE` / `WARN_FORFEITS_DAILY_INCREASE`
- `FAIL_ESCROW_NONZERO_HOURS` / `WARN_ESCROW_NONZERO_HOURS`
- `CI_HARD_FAIL_ON_WARN=1`（WARN 也返回非 0）

Runbook：`docs/runbooks/pr6-alert-rules.md`

## PR-7 Alert Delivery（告警投递）

将 PR-6 `WARN/FAIL` 告警投递到消息通道（Slack webhook 或 Telegram bot），并提供窗口去重防抖。

执行（推荐串联）：

```bash
DRY_RUN=1 ALERT_NOTIFY_CHANNEL=slack ./scripts/v2/pr7_alert_delivery_gate.sh
```

常用环境变量：
- `ALERT_NOTIFY_CHANNEL=slack|telegram`
- `ALERT_NOTIFY_MIN_LEVEL=WARN|FAIL`
- `ALERT_NOTIFY_DEDUP_SECONDS=1800`
- `ALERT_NOTIFY_STATE_FILE=run/pr7-alert-delivery/state.json`
- `DRY_RUN=1`（本地演示，不依赖真实密钥）
- Slack: `SLACK_WEBHOOK_URL`
- Telegram: `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`

Runbook：`docs/runbooks/pr7-alert-delivery.md`

## PR-6 Nightly Security 日报（自动化）

nightly 在流程末尾自动生成日报：

- 产物：`run/pr6-ops/daily-security-summary.md`
- 本地手动重跑：`python3 ./scripts/v2/pr6_daily_security_summary.py`
- Workflow Summary 小节：`PR-6 Daily Security Ops`

Runbook：`docs/runbooks/pr6-nightly-security-summary.md`

## PR-9 Weekly Alert Governance（每周告警治理）

每周治理报告（非阻断）聚合以下指标：告警总量、抑制率、失败率、TopN异常、阈值建议变更。

执行：

```bash
python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

默认输出：
- `run/pr9/weekly-alert-governance.md`

nightly 接入建议：
- workflow step 使用 `continue-on-error: true`
- 上传 `run/pr9/**` 到 artifacts
- Step Summary 增加 `PR-9 Weekly Alert Governance`

Runbook：`docs/runbooks/pr9-weekly-alert-governance.md`

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

