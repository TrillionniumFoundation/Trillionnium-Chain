# Current Codebase Map (Rust L1 Mainline)

Last updated: 2026-02-25

## Monorepo Top-Level

- `trillionnium-rust/` — Rust L1 workspace (core runtime + tooling)
- `scripts/` — automation scripts (gate, relay, smoke, challenge, ops)
- `docs/` — protocol, architecture, runbooks, reports, product docs
- `run/` — runtime artifacts for recent executions
- `data/` — persistent historical artifacts (acceptance, replay, reports)
- `legacy/` — archived legacy stack (non-mainline)

## Rust Workspace (`trillionnium-rust/crates`)

- `trnm-node` — node loop / execution wiring / event emission
- `trnm-types` — shared core types
- `trnm-state` — versioned state storage + state root
- `trnm-pouw` — PoUW state machine (create/commit/reveal/challenge/resolve)
- `trnm-executor` — conflict detection + parallel grouping
- `trnm-mempool` — mempool & packing policy
- `trnm-rpc` — stable query & API schema exposure
- `trnm-bench` — workload benchmark harness
- `trnm-worker-agent` — worker pull/execute/commit-reveal submission agent
- `trnm-cli` — native tx/query CLI (strict gate capable)

## Primary Entrypoints

### Gates / Regression

- `scripts/p0_merge_gate.sh`
- `scripts/p1_negative_suite.sh`
- `scripts/v2/run_worker_receipt_gates.sh`
- `scripts/v2/run_worker_receipt_gates_real_cli.sh`
- `scripts/quick_gate_shell.sh`

### Relay / Automation

- `scripts/auto_relay.sh`
- `scripts/run_100step_pipeline.sh`
- `scripts/run_200step_pipeline.sh`
- `scripts/run_200step_v2_pipeline.sh`
- `scripts/run_codegen_pipeline.sh`

### Demo / Product Smoke

- `scripts/demo_storyline.sh`
- `scripts/min_explorer.py`
- `run/product-smoke/` (artifact sink)

## Artifact Conventions

- Operational short-lived logs: `run/<topic>/` (or `run/logs/`)
- Acceptance / benchmark / replay evidence: `data/<topic>/<timestamp>/`
- Release snapshots: `trillionnium-rust/release/`

## Notes

- Treat `trillionnium-rust/` as the only active protocol/runtime mainline.
- Legacy historical references should stay under `legacy/` and must not be used as default onboarding path.
