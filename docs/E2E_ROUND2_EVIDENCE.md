# E2E Round-2 Evidence (Compute Completion + Settlement Closure)

Date: 2026-02-18 (Asia/Shanghai)
Environment: local dev chain (`chain`, RPC `http://127.0.0.1:26657`)

## Goal
Verify end-to-end lifecycle closure:
- request execution (`CREATED -> RUNNING`)
- complete job (`RUNNING -> COMPLETED`)
- workload task synced (`status=2`, `worker`, `result_hash`)

## Preconditions
- Worker registered on workload module (alice)
- `alice` has enough stake-denom balance for worker registration threshold

## Key Transactions
- request-job-execution tx:
  - `C1FED0472068535ACAF00F6F9584CD3EC21EFA24BD777203ED953C99B2EF27ED`
- complete-job tx:
  - `DA98F55FD57C62DB6E612C367524F7E9B42DF7DAC5D9653C241F79B11DBFD3BB`

## Smoke Output (SUMMARY_JSON)
```json
{"status":"ok","job_id":"0","task_id":"0","tx_complete":"DA98F55FD57C62DB6E612C367524F7E9B42DF7DAC5D9653C241F79B11DBFD3BB","worker":"trnm1nac4jkge88yn83f7cnnvzm4kma0mfr6gjqncxt","result_hash":"sha256:smoke-1771386544","last_step":"[3/3] verify workload task state","duration_s":3}
```

## Command Used
```bash
cd chain
BIN=./chaind SUMMARY_JSON=1 ./tools/compute_lifecycle_smoke.sh 0 alice chain http://127.0.0.1:26657
```

## Result
- ✅ Lifecycle closure verified on-chain
- ✅ Compute and Workload state transitions synchronized
- ✅ Script emits machine-readable success summary for CI/automation
