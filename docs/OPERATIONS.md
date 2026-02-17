# OPERATIONS.md

Practical operator runbook for Trillionnium Chain (`chain/`) mainline.

## 0) Prerequisites
- Ignite CLI installed
- `jq` installed
- Local keyring has `alice` account

## 1) Start Local Chain
```bash
cd chain
ignite chain serve
```

In another terminal:
```bash
cd chain
chaind status | jq '.SyncInfo.latest_block_height'
```

## 2) Check Workload Params
```bash
chaind q workload params -o json
```

Expected default:
- `workloadDenom: "utrnm"`

## 3) Update Economic Denom (Authority Path)
> `update-params` requires module authority signer semantics.

```bash
AUTHORITY=$(chaind q auth module-account gov -o json | jq -r '.account.base_account.address')

chaind tx workload update-params \
  "$AUTHORITY" \
  '{"workloadDenom":"ufoo"}' \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

Re-check:
```bash
chaind q workload params -o json
```

## 4) Task Escrow + Burn Flow
### 4.1 Create Task (escrow to module)
```bash
chaind tx workload create-task \
  --bounty 100 \
  --ipfs-hash QmDemoTask \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 4.2 Complete Task (100% bounty burn)
```bash
chaind tx workload update-task \
  --id 0 \
  --status 2 \
  --result-hash QmDemoResult \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

## 5) Worker Lifecycle
### 5.1 Register Worker (stake lock)
```bash
chaind tx workload register-worker \
  --node-id node-1 \
  --ipfs-addr /ip4/127.0.0.1/tcp/4001 \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 5.2 Request Unbonding
```bash
chaind tx workload request-unbonding \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 5.3 Finalize Unbonding (after cooldown)
```bash
chaind tx workload finalize-unbonding \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

## 6) Governance Safety Hooks
### 6.1 Slash Worker (authority only)
```bash
chaind tx workload slash-worker \
  --worker <worker_addr> \
  --slash-percent 10 \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 6.2 Extend Unbonding (authority only)
```bash
chaind tx workload extend-unbonding \
  --worker <worker_addr> \
  --extra-blocks 50 \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

## 7) Event Checks
Use tx query to inspect emitted events:
- `workload_create_task`
- `workload_update_task`
- `workload_register_worker`
- `workload_slash_worker`
- `workload_request_unbonding`
- `workload_finalize_unbonding`
- `workload_extend_unbonding`

Example:
```bash
chaind q tx <TX_HASH> -o json | jq '.events'
```

## 8) Fast Demo Script
One-command denom governance demo (with tx hash output + event verification):
```bash
cd chain
./tools/demo_denom_governance_flow.sh chain alice http://127.0.0.1:26657 ufoo
```

## 9) Worker Lifecycle Smoke (cooldown + finalize + event checks)
`tools/lifecycle_smoke.sh` now performs end-to-end lifecycle automation:
- register worker
- request unbonding
- parse `releaseHeight` and wait until cooldown is reached
- finalize unbonding
- verify `workload_request_unbonding` / `workload_finalize_unbonding` event attributes
- assert request/finalize amount denom is linked to live `q workload params` denom
- verify unbonding record is removed

Example:
```bash
cd chain
./tools/lifecycle_smoke.sh chain alice http://127.0.0.1:26657
```

Optional env knobs:
- `SLEEP_SECONDS` (default `2`): polling interval during cooldown wait
- `MAX_WAIT_BLOCKS` (default `300`): guardrail to fail fast when chain stalls
- `TX_WAIT_SECONDS` (default `30`): tx inclusion timeout per step
- `SUMMARY_JSON` (default `0`): print one-line machine-readable JSON summary (`SUMMARY_JSON: {...}`) for CI collection (success + failure snapshots)
- `SUMMARY_SCHEMA_VERSION` (default `1`): explicit schema version embedded in summary payload for parser compatibility (`>=3` enables grouped fields for migration preflight)

### 9.1 `SUMMARY_JSON` schema (stabilized for CI)
When `SUMMARY_JSON=1`, the script always emits the same top-level fields (both success and failure), so downstream parsers can rely on a fixed schema.

```json
{
  "schema_version": 1,
  "status": "ok|failed",
  "reason": "",
  "worker": "cosmos1...",
  "last_step": "finalize-unbonding",
  "last_tx": "<txhash>",
  "tx_register": "<txhash>",
  "tx_request_unbonding": "<txhash>",
  "tx_finalize_unbonding": "<txhash>",
  "start_height": 100,
  "end_height": 120,
  "height_delta": 20,
  "duration_s": 18,
  "release_height": 115,
  "cooldown_waited_blocks": 15,
  "cooldown_stagnant_rounds": 0,
  "node_height": "120",
  "catching_up": "false"
}
```

Notes:
- `schema_version=1/2`: flat stable payload (legacy parsers).
- `schema_version>=3`: keeps all flat keys **and** adds grouped fields for migration:
  - `phase_txs.{register,request_unbonding,finalize_unbonding}`
  - `timing.{start_height,end_height,height_delta,duration_s,release_height,cooldown_waited_blocks,cooldown_stagnant_rounds}`
  - `node.{height,catching_up}`
- `status="ok"` on success, `status="failed"` on failure snapshots.
- `reason` is empty on success and contains the failure reason on errors.
- Numeric fields stay numeric even on failures (defaulting to `0` when unavailable early).
- Schema regressions are guarded by `tools/lifecycle_smoke_observability_test.sh` (includes v2 passthrough + v3 preflight compatibility checks).
- Compatibility contract reference: `chain/tools/LIFECYCLE_SUMMARY_SCHEMA_CONTRACT.md`.
- Failure snapshots are also validated for field consistency (`last_step`/`last_tx` textual snapshot lines vs `SUMMARY_JSON` payload), including early failures (e.g. request-denom mismatch) and finalize broadcast failures.

### 9.2 CI parse `SUMMARY_JSON` example
```bash
cd chain
LOG_FILE="/tmp/lifecycle_smoke.log"
SUMMARY_JSON=1 ./tools/lifecycle_smoke.sh chain alice http://127.0.0.1:26657 | tee "$LOG_FILE"

# Extract the latest SUMMARY_JSON payload and parse fields for CI annotations.
SUMMARY_LINE="$(grep 'SUMMARY_JSON:' "$LOG_FILE" | tail -n1)"
SUMMARY_PAYLOAD="${SUMMARY_LINE#*SUMMARY_JSON: }"

echo "$SUMMARY_PAYLOAD" | jq -r '.status // "ok"'
# v3-first, fallback to v1/v2 flat keys
echo "$SUMMARY_PAYLOAD" | jq -r '.phase_txs.finalize_unbonding // .tx_finalize_unbonding // .last_tx // ""'
echo "$SUMMARY_PAYLOAD" | jq -r '"waited_blocks=\(.timing.cooldown_waited_blocks // .cooldown_waited_blocks // 0) stagnant_rounds=\(.timing.cooldown_stagnant_rounds // .cooldown_stagnant_rounds // 0)"'
```

## 10) Troubleshooting (Lifecycle Smoke)
### 10.1 `tx not found in time`
Symptom from script:
- `tx not found in time: tx=<hash> waited=<s> height=<h> catching_up=<bool>`

Checks:
```bash
chaind status --node http://127.0.0.1:26657 | jq '.SyncInfo'
chaind q tx <TX_HASH> --node http://127.0.0.1:26657 -o json
```

Actions:
- If `catching_up=true`, wait for node to finish syncing before re-running.
- Increase `TX_WAIT_SECONDS` for slower local environments.

### 10.2 Cooldown wait timeout / stall
Symptom from script:
- `cooldown wait timeout: current=<h> release=<h> waited_blocks=<n> ...`
- periodic `cooldown stall diagnose` lines every 5 stagnant polls

Checks:
```bash
chaind status --node http://127.0.0.1:26657 | jq '.SyncInfo'
chaind q workload show-unbonding <WORKER_ADDR> --node http://127.0.0.1:26657 -o json
```

Actions:
- Confirm chain is producing blocks (`latest_block_height` increasing).
- Increase `MAX_WAIT_BLOCKS` when block time is intentionally high.
- Reduce `SLEEP_SECONDS` when testing in very short epochs.

### 10.3 Broadcast failed (`code != 0`)
Symptom from script:
- `<label> broadcast failed: txhash=<hash> code=<code> raw_log=<log>`

Checks:
```bash
chaind q tx <TX_HASH> --node http://127.0.0.1:26657 -o json | jq '.raw_log,.events'
```

Typical causes:
- worker already registered
- insufficient fees / balance
- finalize called before cooldown release height

### 10.4 Fast rerun recipe
```bash
cd chain
SLEEP_SECONDS=1 MAX_WAIT_BLOCKS=500 TX_WAIT_SECONDS=60 SUMMARY_JSON=1 ./tools/lifecycle_smoke.sh chain alice http://127.0.0.1:26657
```

### 10.5 Ops regression (mocked smoke observability)
```bash
cd chain
./tools/lifecycle_smoke_observability_test.sh
```
This regression uses a mocked `chaind` to verify lifecycle smoke summary fields and JSON output format stay stable for CI/automation consumers.
