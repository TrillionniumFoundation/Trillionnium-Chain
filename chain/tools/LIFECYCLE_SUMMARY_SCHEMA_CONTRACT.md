# Lifecycle Smoke `SUMMARY_JSON` Schema Contract (v2/v3)

This document defines the compatibility contract for `chain/tools/lifecycle_smoke.sh` JSON summary output.

- Producer: `lifecycle_smoke.sh` when `SUMMARY_JSON=1`
- Consumer examples: CI regression checks, observability parsers
- Version selector: `SUMMARY_SCHEMA_VERSION` (default `1`)

## Compatibility Rules

1. **v1/v2 remain flat**: existing top-level keys stay available.
2. **v3 is additive**: keeps flat keys and adds grouped nested objects.
3. Consumers should parse with fallback order:
   - nested (v3) -> flat (v1/v2) -> legacy fallback where applicable.

Suggested parser fallback for finalize tx hash:

```jq
.phase_txs.finalize_unbonding // .tx_finalize_unbonding // .last_tx // ""
```

## v2 Contract

`SUMMARY_SCHEMA_VERSION=2` preserves flat schema (same shape as v1) with:

- `schema_version: 2`
- **No required nested groups** (e.g. `phase_txs` not required)

Required top-level fields (same as v1):

- `schema_version`, `status`, `reason`, `worker`, `last_step`, `last_tx`
- `tx_register`, `tx_request_unbonding`, `tx_finalize_unbonding`
- `start_height`, `end_height`, `height_delta`, `duration_s`
- `release_height`, `cooldown_waited_blocks`, `cooldown_stagnant_rounds`
- `node_height`, `catching_up`

## v3 Contract

`SUMMARY_SCHEMA_VERSION=3` includes all flat fields above **plus** grouped fields:

- `phase_txs`
  - `register`
  - `request_unbonding`
  - `finalize_unbonding`
- `timing`
  - `start_height`
  - `end_height`
  - `height_delta`
  - `duration_s`
  - `release_height`
  - `cooldown_waited_blocks`
  - `cooldown_stagnant_rounds`
- `node`
  - `height`
  - `catching_up`

### Status Semantics

- `status="ok"`: full lifecycle completed and checks passed.
- `status="failed"`: script aborted; summary contains last known diagnostics.
- `reason`: empty on success, failure reason on error.

## Contract Examples

Example payloads are checked in and intended for downstream parser fixtures:

- `chain/tools/examples/lifecycle_summary_v1_failed.json`
- `chain/tools/examples/lifecycle_summary_v2_ok.json`
- `chain/tools/examples/lifecycle_summary_v3_ok.json`

`chain/tools/lifecycle_summary_parser_examples_test.sh` demonstrates parser fallback extraction for:

- finalize tx hash (`phase_txs.finalize_unbonding -> tx_finalize_unbonding -> last_tx`)
- release height (`timing.release_height -> release_height`)
- node height (`node.height -> node_height`)

## CI Coverage

`chain/tools/lifecycle_smoke_observability_test.sh` validates:

- v2 compatibility (`schema_version == 2`, no required nested keys)
- v3 nested groups and value linkage
- consumer fallback behavior for tx extraction across versions

`chain/tools/lifecycle_summary_parser_examples_test.sh` validates committed fixture samples and parser fallback examples.

This document is a contract baseline for future schema bumps.
