# Worker Gates Strict Default — Release Note (2026-02-21)

## Summary

Worker receipt gates are now in **strict real-cli default mode** across primary CI gates.

## What changed

- `trnm-merge-gates.yml`
  - strict real-cli gate switched to default-on (`REQUIRE_REAL_TX_CLI` default = `1`)
- `rust-l1-nightly-health.yml`
  - strict real-cli gate switched to default-on (`REQUIRE_REAL_TX_CLI` default = `1`)
- Strict gate command path:
  - `./scripts/v2/run_worker_receipt_gates_real_cli.sh`
- Default tx cli for strict mode:
  - `./scripts/v2/trnm_tx_cli_wrapper.sh` (override with `TRNM_TX_CLI`)

## Canonical commands

```bash
# strict gate local run
REQUIRE_REAL_TX_CLI=1 TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_wrapper.sh ./scripts/v2/run_worker_receipt_gates_real_cli.sh

# full relay strict run
REQUIRE_REAL_TX_CLI=1 TRNM_TX_CLI=./scripts/v2/trnm_tx_cli_wrapper.sh STOP_ON_ERROR=1 ROUNDS=1 ./scripts/run_codegen_pipeline.sh
```

## Rollback switch

If needed, strict mode can be disabled temporarily:

```bash
REQUIRE_REAL_TX_CLI=0
```

## Evidence

- Strict relay run passed: `relay-20260221-153625-93955` (ok=21 fail=0)
- Prior strict wrapper path pass recorded via `run_worker_receipt_gates_real_cli.sh`
