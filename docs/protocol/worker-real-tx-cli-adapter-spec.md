# Worker Real TX CLI Adapter Spec (v1)

更新：2026-02-21

## Goal

Define a drop-in real tx CLI adapter so worker strict gates can run against a real chain without changing worker gate scripts.

Canonical strict entry:

```bash
TRNM_TX_CLI=<adapter> ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

## Required Interface

Adapter MUST support:

```bash
<adapter> tx --help
<adapter> tx commit-result <task_id> <worker> <commit_hash> <nonce>
<adapter> tx reveal-result <task_id> <result_hash> <salt_hex>
```

Behavior requirements:
- Success: exit 0, print `tx_hash=<hash>` in stdout or stderr.
- Failure: non-zero exit, print error detail.
- Deterministic validation failures should return non-zero and be retry-safe.

## Environment Contract

Recommended env keys:
- `TRNM_TX_BIN` (e.g. `chaind`)
- `TRNM_RPC`
- `TRNM_CHAIN_ID`
- `TRNM_KEY_NAME`
- `TRNM_KEYRING_BACKEND`
- `TRNM_GAS`, `TRNM_GAS_ADJUSTMENT`, `TRNM_FEES`
- `TRNM_BROADCAST_MODE` (default `sync`)

## Validation Checklist

1. Readiness passes:
```bash
REQUIRE_REAL_TX_CLI=1 TRNM_TX_CLI=<adapter> ./scripts/v2/worker_real_cli_readiness.sh
```

2. Strict gates pass:
```bash
TRNM_TX_CLI=<adapter> ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

3. Evidence capture:
- save strict gate logs
- keep ack log with `accepted/rejected/failed`
- keep tx hash samples (commit + reveal)

## Starter Template

Use:
- `scripts/v2/trnm_tx_cli_real_adapter.template.sh`

Copy it to your env-specific adapter and replace TODO tx commands with real chain tx paths.
