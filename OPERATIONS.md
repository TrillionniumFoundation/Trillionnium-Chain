# Operations Manual

> Scope: main Trillionnium repository operational playbook (English rewrite).

## Canonical Public-Testnet Candidate

- Run the application with `trnm-cometbft-app` beside a pinned CometBFT node.
  Canonical state transition is `CometBFT -> trnm-consensus-app -> trnm-runtime`.
- `trnm-chain-node`, `trnm-chain-validator`, `trnm-chain-cli`, and `trnm-sim`
  are frozen legacy harnesses. They require the explicit `legacy-harness`
  Cargo feature and their output is not release or finality evidence.
- The historical `trnm_chain_devnet_v1` signed package is retained only for
  reproducibility audits. Building it requires an explicit
  `TRNM_LEGACY_HARNESS_ACKNOWLEDGED=1` acknowledgement and does not produce a
  public-testnet artifact.
- Production packaging, remote-signer integration, and multi-host rollout are
  still open readiness items; see `RELEASE_READINESS.md`.

## Workload Module

### RequestUnbonding

The `RequestUnbonding` message allows a worker to initiate unbonding of their stake.

#### Business Logic
1. **Validation**:
   * Validate that the request is not nil.
   * Verify creator address format.
   * Ensure the worker exists (`ErrWorkerNotFound`).
   * **Stake check**: require a non-zero stake. If `Stake == 0`, reject with `ErrInvalidRequest` (`worker has no stake to unbond`).
   * Ensure no unbonding request already exists for the worker (`ErrUnbondingAlreadyRequested`).
   * Verify block height is within safe bounds.

2. **Execution**:
   * Compute release height as (`CurrentHeight + UnbondingPeriodBlocks`).
   * Create an `Unbonding` record with computed release height and current worker stake.
   * Remove the `Worker` record immediately (worker exits active set).
   * Emit `workload_request_unbonding` event.


### FinalizeUnbonding

The `FinalizeUnbonding` message allows a user to claim unbonded tokens after the cooldown elapses.

#### Business Logic
1. **Validation**:
   * Validate that the request is not nil.
   * Verify creator address format.
   * Check that an `Unbonding` record exists for the creator (`ErrUnbondingNotFound`).
   * Check whether current block height is at least the `ReleaseHeight` (`ErrUnbondingCooldownNotReached`).

2. **Execution**:
   * Read stored unbonding amount.
   * Transfer tokens from module account back to user account via BankKeeper.
   * Remove `Unbonding` record from store.
   * Emit `workload_finalize_unbonding` event.

#### State Consistency
* **Worker removal**: `Worker` is removed during `RequestUnbonding`; `FinalizeUnbonding` ensures no stale "zombie" worker entries remain.
* **Unbonding cleanup**: remove `Unbonding` record only after successful finalization to avoid duplicate reclaim.

### Test Coverage
* `x/workload/keeper`: ~92.7%
* New test `TestFinalizeUnbonding_StateConsistency` covers:
  1. Worker record is removed after `RequestUnbonding`.
  2. Unbonding record is created correctly.
  3. After `FinalizeUnbonding`, both worker and unbonding records are absent.

## Compute Module

### CreateComputeJob

The `CreateComputeJob` message lets a user submit compute work that becomes a Workload task.

#### Business Logic
1. **Validation**:
   * Reject empty payload (`ErrInvalidPayload`).
   * Verify creator address format.

2. **Execution**:
   * Create a `Task` in Workload with payload stored as `IpfsHash`.
   * Return new `JobId` (same as Workload task ID).

### Integration Test
* `TestCreateComputeJob_Integration`:
  * Verifies that `CreateComputeJob` creates corresponding `Workload` task.
  * Queries by returned `JobId` to validate side effects.
  * Checks empty payload rejection path.

## Product-layer minimal API smoke (Create Account -> Balance -> Transfer -> GetTx)

> Goal: provide a scriptable sequence that validates the minimal product-layer transaction loop.

### Prerequisites
- RPC endpoint reachable (default `http://127.0.0.1:8545`)
- Test accounts funded (local dev/faucet acceptable)

### 1) Create accounts (example)

```bash
# Example: generate two test addresses locally; replace with your wallet addresses if needed
ALICE_ADDR=${ALICE_ADDR:-trnm1alice...}
BOB_ADDR=${BOB_ADDR:-trnm1bob...}
RPC_URL=${RPC_URL:-http://127.0.0.1:8545}
```

### 2) Query balance

```bash
curl -sS "$RPC_URL" -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":1,
  "method":"balance",
  "params":{"address":"$ALICE_ADDR"}
}'
```

### 3) Transfer (nonce + sendTx)

```bash
# Get nonce first
NONCE=$(curl -sS "$RPC_URL" -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":2,
  "method":"nonce",
  "params":{"address":"$ALICE_ADDR"}
}' | jq -r '.result.nonce')

# Submit tx (replace signature with your signer/wallet implementation)
TX_HASH=$(curl -sS "$RPC_URL" -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":3,
  "method":"sendTx",
  "params":{
    "from":"$ALICE_ADDR",
    "to":"$BOB_ADDR",
    "amount":"1000000",
    "denom":"utrnm",
    "nonce":$NONCE,
    "signature":"0x..."
  }
}' | jq -r '.result.txHash')

echo "tx_hash=$TX_HASH"
```

### 4) Query transaction (getTx)

```bash
curl -sS "$RPC_URL" -H 'content-type: application/json' -d '{
  "jsonrpc":"2.0",
  "id":4,
  "method":"getTx",
  "params":{"txHash":"$TX_HASH"}
}'
```

### One-command smoke (recommended)

```bash
cd /Users/qianqi/.openclaw/workspace/TrillionniumChain
./scripts/v2/product_layer_smoke.sh
```

The standard output prints explicit PASS/FAIL fields, such as:
- `address`
- `tx_hash`
- `status`

Optional environment variables:
- `CLI_BIN` (default `cargo run -q -p trnm-cli --`)
- `WALLET_STORE` / `RUN_DIR`
- `ALICE_NAME` / `BOB_NAME`
- `TRANSFER_AMOUNT` / `DENOM`

### Pass criteria
- `wallet create` succeeds and prints `address`
- `query balance` returns `address/balance`
- `tx transfer` returns `tx_hash`
- `getTx` returns `status`
- script ends with `[SMOKE][PASS] product-layer smoke`

## E2E Worker Runbook (Job -> Execute -> Commit)

### Prerequisites
- Local chain running (`chaind status` returns latest height)
- Docker daemon running
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
2. ensures exactly one worker instance
3. submits N jobs
4. waits for processing
5. checks `worker/worker.log` contains `result committed on-chain` exactly N times

### Pass criteria
- Script exits with code `0`
- Terminal prints `SMOKE PASS ✅`
- Worker log contains entries like:
  - `Submitting MsgCompleteJob for Job <id>...`
  - `✅ Job <id> result committed on-chain`

## Rust Worker Receipt Gate (single entrypoint)

Run from repository root:

```bash
./scripts/v2/run_worker_receipt_gates.sh
```

Notes:
- This is the only supported entrypoint for worker receipt gating (aligned with CI and relay).
- It includes:
  1. `worker_agent_full_loop.sh`
  2. `worker_replay_guard_test.sh`
  3. `worker_failed_receipt_test.sh`
  4. `worker_resume_no_duplicate_test.sh`

Readiness check for real CLI (run before integration):

```bash
./scripts/v2/worker_real_cli_readiness.sh
# Strict mode: non-zero exit when prerequisites are not met
REQUIRE_REAL_TX_CLI=1 ./scripts/v2/worker_real_cli_readiness.sh
```

Full real-cli gate (readiness + receipt gates):

```bash
TRNM_TX_CLI=<your-real-tx-cli> ./scripts/v2/run_worker_receipt_gates_real_cli.sh
# Local minimal wrapper example
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_wrapper.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh
# Rust-native CLI (build first)
TRNM_TX_CLI=./trillionnium/target/debug/trnm-cli ./scripts/v2/run_worker_receipt_gates_real_cli.sh
# Real-chain adapter (configured via env vars)
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_real_adapter.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

Recommended environment template flow:

```bash
cp scripts/v2/worker_real_cli.env.example /tmp/worker_real_cli.env
# Edit TRNM_TX_COMMIT_CMD / TRNM_TX_REVEAL_CMD inside /tmp/worker_real_cli.env
source /tmp/worker_real_cli.env
TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_real_adapter.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

Adapter spec/template references:
- Spec: `docs/protocol/worker-real-tx-cli-adapter-spec.md`
- Template: `scripts/v2/trnm_tx_cli_real_adapter.template.sh`

### PR-1 companion gates (Tests-Docs)

Run from repository root:

```bash
./scripts/v2/rpc_query_hardcap_enforcement_test.sh
./scripts/v2/governance_value_schema_reject_test.sh
./scripts/v2/worker_real_cli_fake_wrapper_block_test.sh
```

Gate notes:
- `rpc_query_hardcap_enforcement_test.sh`: verifies query hard-cap clamp behavior (cap upper bound, and zero falling back to default).
- `governance_value_schema_reject_test.sh`: verifies invalid u64 / non-strict bool governance params are rejected.
- `worker_real_cli_fake_wrapper_block_test.sh`: verifies strict real-cli gate blocks fake wrapper (must exit non-zero).

Recommended set: combine the three checks above with `run_worker_receipt_gates_real_cli.sh` as PR-1 minimum acceptance.

### PR-2 companion gates (Timeout + Challenge Bond)

> BL09 retirement-prep note: retained `pouw_*` gate names in this section are migration-era compatibility and audit-evidence guardrails only. They keep legacy timeout and challenge coverage reviewable during cutover, but they do not imply that PoUW remains the default payout authority or default work-unit payout path once PoCO settlement is primary.

Run from repository root:

```bash
./scripts/v2/pouw_commit_timeout_migration_test.sh
./scripts/v2/pouw_challenge_timeout_migration_test.sh
./scripts/v2/challenge_bond_enforcement_test.sh
```

Gate notes:
- `pouw_commit_timeout_migration_test.sh`: scans and executes `commit -> timeout` migration tests (keywords: `commit + timeout + migration`).
- `pouw_challenge_timeout_migration_test.sh`: scans and executes `challenge -> timeout` migration tests (keywords: `challenge + timeout + migration`).
- `challenge_bond_enforcement_test.sh`: scans and executes challenge bond enforcement tests (keywords: `challenge + bond + enforce/min`).

PR-2 acceptance list:
- [ ] All three scripts exit with code 0
- [ ] Target tests are actually executed (non-zero test count)
- [ ] `commit` timeout migration path covered
- [ ] `challenge` timeout migration path covered
- [ ] minimum bond / bond enforcement rejection path covered

> Note: each script discovers tests via `cargo test -- --list` by keyword; it fails immediately if no matching tests are found. This is intentional to avoid green checks with missing test coverage.

### PR-4 gate (forfeited funds flow + audit field visibility)

Run from repository root:

```bash
./scripts/v2/pr4_challenge_fundflow_audit_gate.sh
```

Gate notes:
- `bond_forfeiture_flow_test`: verifies challenge failure forfeits bond path (`challenge_bond_forfeited=true`).
- `bond_refund_flow_test`: verifies successful challenge + worker slash returns challenger bond (`challenge_bond_forfeited=false`).
- `event_audit_fields_visibility`: checks resolve event exposes audit fields (must include `signer/challenger/tx_hash/slash_worker/resolution_code`).

Artifacts:
- default output dir: `run/pr4-gates/<timestamp>/` (UTC)
- summary: `summary.txt` (includes `generated_at_utc`)
- per-step logs: `bond_forfeiture_flow_test.log` / `bond_refund_flow_test.log` / `event_audit_fields_visibility.log`

PR-4 acceptance checklist:
- [ ] Script exits 0
- [ ] `summary.txt` contains `status=PASS`
- [ ] Forfeiture path passes
- [ ] Refund path passes
- [ ] resolve event includes `signer/challenger/tx_hash/slash_worker/resolution_code`

### PR-5 operations query and reconciliation (Challenge Treasury / Forfeits)

#### A) Fast query by task

Run in `trillionnium/`:

```bash
# Query single task event trail, including challenge/resolve audit fields
cargo run -q -p trnm-rpc -- query-events --task-id <TASK_ID> --limit 100
```

Key fields:
- `event_type` (`challenge` / `resolve`)
- `treasury_delta`
- `challenger_delta`
- `bond_disposition` (`posted/forfeited/refunded`)
- `resolution_code`

#### B) Daily reconciliation (log aggregation)

Run from repository root:

```bash
./scripts/v2/pr5_treasury_reconcile_report.sh
```

The script auto-selects event-log source (preferred: `trillionnium/run/event-field-check.log`) and outputs:
- `run/pr5-reconcile/<timestamp>/summary.txt`
- `run/pr5-reconcile/<timestamp>/reconcile.json`

Optional args:
- `SOURCE_LOG=<path>`: force log input
- `OUT_DIR=<path>`: custom output directory

#### C) PR-5 acceptance checklist

- [ ] `query-events` can return `challenge/resolve` events
- [ ] Output contains `treasury_delta/challenger_delta/bond_disposition`
- [ ] `pr5_treasury_reconcile_report.sh` successfully writes `summary.txt`
- [ ] `summary.txt` has `status=PASS`

For more details see `docs/runbooks/l19_ops_observability_alerting_reconcile_runbook.md` PR-5 section; inline script help is authoritative for exact implementation details.

## PR-6 Alert Rules (Challenge Treasury Anomaly Alerts)

Run:

```bash
./scripts/v2/pr6_alert_rules_gate.sh
```

Default output:
- `run/pr6-alerts/<timestamp>/summary.txt` (timestamped by UTC)
- machine-parseable fields: `status=PASS|WARN|FAIL` and `rule.*`

Threshold env vars:
- `FAIL_UNRESOLVED_CHALLENGES` / `WARN_UNRESOLVED_CHALLENGES`
- `FAIL_FORFEITS_DAILY_INCREASE` / `WARN_FORFEITS_DAILY_INCREASE`
- `FAIL_ESCROW_NONZERO_HOURS` / `WARN_ESCROW_NONZERO_HOURS`
- `CI_HARD_FAIL_ON_WARN=1` (make WARN return non-zero)

Runbook: see `docs/runbooks/l19_ops_observability_alerting_reconcile_runbook.md` PR-6 section. If behavior conflicts, `./scripts/v2/pr6_alert_rules_gate.sh` and generated `run/pr6-alerts/*/summary.txt` take precedence.

## PR-7 Alert Delivery

Use this gate to deliver PR-6 `WARN`/`FAIL` alerts to Slack/Telegram and apply windowed de-duplication.

Run (recommended chain):

```bash
DRY_RUN=1 ALERT_NOTIFY_CHANNEL=slack ./scripts/v2/pr7_alert_delivery_gate.sh
```

Common env vars:
- `ALERT_NOTIFY_CHANNEL=slack|telegram|imessage`
- `ALERT_NOTIFY_PRIMARY_CHANNEL`
- `ALERT_NOTIFY_BACKUP_CHANNEL`
- `ALERT_NOTIFY_MIN_LEVEL=INFO|WARN|CRITICAL` (`PASS->INFO`, `FAIL->CRITICAL` aliases accepted)
- `ALERT_NOTIFY_DEDUP_SECONDS=1800`
- `ALERT_NOTIFY_STATE_FILE=run/pr7-alert-delivery/state.json`
- `ALERT_NOTIFY_AUDIT_FILE=run/pr7-alert-delivery/audit.jsonl`
- `ALERT_NOTIFY_DEAD_LETTER_FILE=run/pr7-alert-delivery/dead-letter.jsonl`
- `ALERT_NOTIFY_GLOBAL_RETRY_BUDGET_STATE_FILE=run/pr7-alert-delivery/retry-budget-state.json`
- `PR7_DELIVERY_FAIL_MODE=ignore|warn|escalate` (default ignore; escalate raises final gate code to 4 on delivery failure)
- `DRY_RUN=1` (local simulation without real credentials)
- Slack: `SLACK_WEBHOOK_URL`
- Telegram: `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`
- iMessage: `IMESSAGE_TO`

Troubleshooting artifacts:
- `run/pr7-alerts/<timestamp>-pid*/summary.txt`: raw alert summary from PR-6
- `run/pr7-alerts/<timestamp>-pid*/policy.env`: policy snapshot used in this PR-6/PR-7 chain
- `run/pr7-alerts/<timestamp>-pid*/pr7-delivery-status.env`: final PR-7 status fields (`status/pr6_rc/pr7_rc/final_rc/fail_mode/delivery_event/primary_channel/backup_channel/success_channels/failed_channels/channels_ok/channels_failed/partial_success/run_dir/lock_dir/report/audit_file/generated_at_utc`)
- `run/pr7-alert-delivery/state.json`: cumulative delivery/suppression/failure counters and latest metadata
- `run/pr7-alert-delivery/audit.jsonl`: per-attempt delivery/suppression/fail audit stream
- `run/pr7-alert-delivery/dead-letter.jsonl`: dead-letter after retry exhaustion
- `run/pr7-alert-delivery/retry-budget-state.json`: cross-run global retry budget

Suggestion:
- For local dry runs use `PR7_DELIVERY_FAIL_MODE=warn` to keep `pr7_rc` visible without turning temporary channel failure into gate failure.
- For workflows requiring "alerts must page when delivery fails": set `PR7_DELIVERY_FAIL_MODE=escalate`.

Runbook: see `docs/runbooks/l19_ops_observability_alerting_reconcile_runbook.md` PR-7 section. If behavior conflicts, prefer outputs from `./scripts/v2/pr7_alert_delivery_gate.sh`, `scripts/v2/pr7_alert_delivery.py`, and `run/pr7-alerts/*`.

## PR-6 Nightly Security Summary (automated)

Nightly at the end of the flow generates:

- artifact: `run/pr6-ops/daily-security-summary.md`
- local rerun: `python3 ./scripts/v2/pr6_daily_security_summary.py`
- workflow summary section label: `PR-6 Daily Security Ops`

Runbook: see `docs/runbooks/l19_ops_observability_alerting_reconcile_runbook.md` PR-6 Nightly Daily Security Summary section. If behavior conflicts, trust script output at `run/pr6-ops/daily-security-summary.md` produced by `python3 ./scripts/v2/pr6_daily_security_summary.py`.

## PR-9 Weekly Alert Governance (weekly alert governance)

The weekly governance report (non-blocking) aggregates:
- total alerts,
- suppression rate,
- fail rate,
- actual delivery success rate,
- suppression share,
- TopN anomalies,
- threshold advice changes.

Run:

```bash
python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

Default outputs:
- `run/pr9/weekly-alert-governance.md`
- `run/pr9/weekly-alert-governance.json`
- `run/pr9/history/weekly-alert-governance-YYYYMMDDTHHMMSSZ.json`

Best-effort inputs (missing data does not hard-fail):
- `run/pr7-alert-delivery/state.json` delivery stats (`alerts_sent / alerts_suppressed / alerts_failed`)
- `run/pr7-alert-delivery/dead-letter.jsonl` dead-letter count in `--lookback-days` window
- `run/pr7-topn/*/topn-anomaly-summary.md` latest TopN unresolved / forfeit / escrow summaries
- `run/pr7-threshold-advisor/*/threshold-advice.json` latest threshold advice
- `run/pr9/alert-thresholds.env` / `run/pr9/alert-thresholds.previous.env` threshold env diff
- `run/pr9/history/weekly-alert-governance-*.json` last-week baseline (for WoW diff; ignores future-stray snapshots)

Optional params:
- `--lookback-days <n>` dead-letter and weekly comparison window (default 7)
- `--top-n <n>` TopN size in output (default 5)
- `--out <path>` markdown output path
- `--json-out <path>` JSON output path
- `--history-dir <path>` history snapshot directory

Degradation/missing-data behavior:
- if baseline missing, marks `baseline unavailable` but still writes current `.md/.json`
- if PR7 TopN or threshold advice missing, marks `MISSING` / `unavailable` in JSON `degraded.*` and markdown note
- if current JSON payload matches latest historical payload exactly, PR-9 skips duplicate write and refreshes only current outputs
- baseline selection ignores future-timestamp snapshots to avoid WoW contamination

Nightly integration guidance:
- workflow step: `continue-on-error: true`
- upload `run/pr9/**` as artifacts
- workflow summary section: `PR-9 Weekly Alert Governance`

Recommended pre-step (for richer report):

```bash
./scripts/v2/pr7_topn_summary_gate.sh
python3 ./scripts/v2/pr7_threshold_advisor.py
python3 ./scripts/v2/pr9_weekly_alert_governance.py
```

Runbook: see `docs/runbooks/l19_ops_observability_alerting_reconcile_runbook.md` PR-9 section. If behavior conflicts, use generated `run/pr9/weekly-alert-governance.md` / `.json` from script output.

## Agent↔User P2P Phase A (MVP)

Primary docs: `docs/protocol/agent-user-p2p-phaseA-ops.md`

Supplemental operations doc (batch ack / retry cut-off and triage): `docs/OPERATIONS.md`

Minimum gate command:

```bash
cd trillionnium
./scripts/run_agent_user_phasea_gate.sh
```

Default uses sqlite persistence for reliability store. Set `RELIABILITY_STORE=memory` to force in-memory mode.

```bash
cd trillionnium
# Override DB path if needed
RELIABILITY_DB_PATH=run/health/reliability-phasea.sqlite \
./scripts/run_agent_user_phasea_gate.sh
```

### 2h Soak Harness (submit/dispatch/worker/query end-to-end loop)

Run from repository root (default duration 2h):

```bash
./scripts/v2/run_reliability_soak.sh
```

Quick smoke (for example 5 minutes):

```bash
./scripts/v2/run_reliability_soak.sh --duration 5m --clean
```

Auditable artifacts:
- `run/health/reliability-soak-<ts>.json`: full metrics and parameters
- `run/health/reliability-soak-<ts>.txt`: human-readable summary
- `run/health/reliability-soak-<ts>.audit.jsonl`: per-cycle event audit trail

Default behavior:
- `RELIABILITY_STORE=sqlite` when not explicitly set
- continuously runs: submit -> dispatch-open -> run-assigned -> flush-submissions -> query-request-full
- aggregates throughput (`submit/terminal TPS`) and success rates (submit success, finality success)

One-shot chained gate (fail-fast): consensus matrix -> proof checks -> Phase A

```bash
cd trillionnium
./scripts/run_phasea_security_oneshot.sh
# Optional: custom root output directory
# RUN_ROOT=/tmp/trnm-gate-oneshot ./scripts/run_phasea_security_oneshot.sh
```

One-shot result interpretation:
- Step 1 (consensus security matrix) summary: `<RUN_ROOT>/consensus-security/summary.txt`
  - `result=PASS`: all matrix items pass
  - `result=FAIL`: at least one item fails (check `*.log` in same folder)
- Step 2 (proof smoke + tamper) log: `<RUN_ROOT>/proof-gate.log`
  - case: `relay_session_proof_smoke_and_tamper_matrix`
  - coverage: missing segment / out-of-order / content tampering / root mismatch
- Step 3 (Phase A) outputs: `<RUN_ROOT>/agent-user-phasea/`
  - report file: `agent-user-phasea-gate-<ts>.txt`
  - required fields include `status=COMMIT_QUEUED`, `verifier_status=accepted`, `status=PASS`

Gate assertions:
- `trnm-rpc` and `trnm-worker-agent` build/tests pass
- proof smoke + tamper case passes (missing segment / order confusion / content tamper / root mismatch)
- minimal end-to-end loop passes: submit/dispatch/consume/query
- `query-request-full` includes `status=COMMIT_QUEUED` and `verifier_status=accepted`

### Phase A one-command rollback (commit/tag)

Run from repository root:

```bash
./scripts/rollback_phasea.sh <commit-or-tag>
# Skip interactive confirmation
./scripts/rollback_phasea.sh <commit-or-tag> --yes
```

Script behavior (exit on first failure):
1. Validate target commit/tag resolves
2. Explicit safety confirmation (default requires typing `ROLLBACK`)
3. Checkout detached target (`git checkout --detach`)
4. Clean runtime state (`devnet_down`, common local processes, temp files)
5. Run minimum verification: `trillionnium/scripts/run_agent_user_phasea_gate.sh`

Safety protections:
- clean working tree required by default; set `ALLOW_DIRTY=1` if override is explicitly needed
- on failure, script prints log paths by default:
  - `run/rollback-phasea/<timestamp>/rollback.log`
  - `run/rollback-phasea/<timestamp>/agent-user-phasea/`
