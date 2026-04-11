# Trillionnium Chain (TRNM)

**TRNM** is a Rust-native Layer 1 focused on **Decentralized AI Compute** (PoUW).

- Active mainline: `trillionnium/`
- Historical archive: `legacy/`

---

## 1) Project Positioning

TRNM is a Rust L1 protocol for task-based AI compute settlement and verification. Its core design goals are:

- **PoUW state machine** for task lifecycle: create → commit → reveal → challenge → resolve
- **High-concurrency execution** with conflict detection and grouped scheduling
- **Auditable events + stable interfaces** for integration, replay, governance, and operations
- **Worker Agent + CLI** loop from execution to on-chain submission

---

## 2) Repository Layout (Current)

```text
TrillionniumChain/
├── trillionnium/                    # Rust workspace (current source-of-truth lane)
│   ├── crates/
│   │   ├── trnm-node
│   │   ├── trnm-types
│   │   ├── trnm-state
│   │   ├── trnm-pouw
│   │   ├── trnm-executor
│   │   ├── trnm-mempool
│   │   ├── trnm-rpc
│   │   ├── trnm-bench
│   │   ├── trnm-worker-agent
│   │   ├── trnm-cli
│   │   └── trnm-bridge-poc
│   ├── configs/
│   ├── scripts/
│   └── run/
├── web4-frontend/                  # Web4 frontend (Next.js + Vitest + Playwright)
├── scripts/                        # Repo-level CI/automation scripts
├── docs/                           # Architecture, protocol, runbooks, and reports
├── contracts/                      # Rust-native external contracts subtree (active MVP scaffolding)
├── config/                         # Policy and alerting config
├── data/                           # Acceptance data and experiment artifacts
├── run/                            # Runtime logs and gate outputs
├── examples/                       # SDK and demo examples
└── legacy/                         # Historical frozen branches / archival code
```

---

## 3) Core Modules

### Rust mainline (`trillionnium/crates`)

- `trnm-node`: node runtime loop, execution wiring, event emission
- `trnm-state`: versioned state store and `state_root`
- `trnm-pouw`: PoUW task state machine and validation logic
- `trnm-executor`: conflict detection and concurrent scheduling strategy
- `trnm-mempool`: transaction pool and admission/packaging
- `trnm-rpc`: RPC service and stable query APIs
- `trnm-worker-agent`: worker execution and on-chain submission path
- `trnm-cli`: native CLI for tx/query operations
- `trnm-bench`: benchmarking and performance tooling
- `trnm-types`: shared protocol types
- `trnm-bridge-poc`: bridge proof-of-concept integration

### Web4 frontend (`web4-frontend`)

- Next.js app shell (`app/`)
- Contract/API adaptation layer (`lib/`)
- Test suites (unit/component/contract/e2e)
- Release preflight scripts in `web4-frontend/scripts/`:
  - `npm run ci:check`
  - `npm run release:preflight`
  - `npm run release:ready`

---

## 4) Quick Start

### 4.1 Environment

- Rust stable (keep aligned with `rust-toolchain`/CI)
- Node.js 20+
- Git

### 4.2 Clone

```bash
git clone https://github.com/ProfAlexQI/TrillionniumChain.git
cd TrillionniumChain
```

### 4.3 Rust mainline smoke

```bash
cd trillionnium
cargo test --workspace
```

### 4.4 Web4 frontend smoke

```bash
cd web4-frontend
npm ci
npm run ci:check
# Force e2e if needed
CI_RUN_E2E=1 npm run ci:check
```

---

## 5) Common Repo Commands

### 5.1 Repo-level gates / pipeline

```bash
# Quick gate
./scripts/quick_gate_shell.sh

# Automation pipelines
./scripts/run_100step_pipeline.sh
./scripts/run_200step_pipeline.sh
./scripts/run_200step_v2_pipeline.sh
./scripts/run_codegen_pipeline.sh
```

### 5.2 Worker / Receipt gates

```bash
# Worker receipt gates
./scripts/v2/run_worker_receipt_gates.sh

# Strict real-cli mode
TRNM_TX_CLI=./trillionnium/target/debug/trnm-cli \
  ./scripts/v2/run_worker_receipt_gates_real_cli.sh
```

### 5.3 Tokenomics regression gate

```bash
./scripts/v2/run_tokenomics_r1_r14_regression_gate.sh
```

---

## 6) Documentation Entry Points

- Release/truth source entry: [RELEASE_READINESS.md](RELEASE_READINESS.md)
  - When referencing this file, include the current `git rev-parse origin/main` value to avoid using stale commit hashes as current truth.
- Project status log: [docs/archive/root-history/STATUS.md](docs/archive/root-history/STATUS.md)
- Historical roadmap: [docs/archive/root-history/ROADMAP.md](docs/archive/root-history/ROADMAP.md)
- Historical backlog snapshots: [docs/archive/root-history/BACKLOG.md](docs/archive/root-history/BACKLOG.md)
- Unified development scheduling (planning board): [docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md](docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md)
- Concurrency bottleneck map + 8-week roadmap: [docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md](docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md)
- External benchmark comparison: [docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md](docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md)
- Web4 platform overview: [docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md](docs/WEB4_INFRA_PLATFORM_DEVELOPMENT_MASTER.md)
- Rust-native external contracts baseline architecture: [trillionnium/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md](trillionnium/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md)
- `contracts/` status and boundaries: [contracts/README.md](contracts/README.md)
- PoUW mechanism: [trillionnium/docs/challenge-economics-minimal.md](trillionnium/docs/challenge-economics-minimal.md)
- A2A adapter contract: [docs/agent/a2a_adapter_contract_v1.md](docs/agent/a2a_adapter_contract_v1.md)
- MCP adapter contract: [docs/agent/mcp_adapter_contract_v1.md](docs/agent/mcp_adapter_contract_v1.md)
- Operations handbook: [OPERATIONS.md](OPERATIONS.md)
- OpenClaw ops micro-runbook: [docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md](docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md)
- Web4 frontend docs: [web4-frontend/README.md](web4-frontend/README.md)
- Web4 documentation center:
  - [web4-frontend/docs/README.md](web4-frontend/docs/README.md)
  - [web4-frontend/docs/developer-guide.md](web4-frontend/docs/developer-guide.md)
  - [web4-frontend/docs/operations-runbook.md](web4-frontend/docs/operations-runbook.md)
  - [web4-frontend/docs/release-checklist.md](web4-frontend/docs/release-checklist.md)

> Quick link check: run `./scripts/check_root_readme_local_links.sh` to verify local links.

---

## 7) CI / Workflows

The repo runs multiple chain/frontend pipelines under `.github/workflows/`, including:

- `trnm-merge-gates.yml`
- `rust-l1-nightly-health.yml`
- `trnm-gate-quick-check.yml`
- `web4-frontend-ci.yml`

Please run the local minimum gates before creating PRs to reduce CI turnarounds.

---

## 8) Current State Notes (Operational Boundaries)

- Main development entry is `trillionnium/`.
- `legacy/` is for archival history only.
- Whether the project is currently **release-ready** is defined by [RELEASE_READINESS.md](RELEASE_READINESS.md); historical evidence documents are not automatically equivalent to live state.
- `contracts/` is an **independent Rust-native external-contract subtree / MVP contract scaffolding**. It is not yet the full `sdk / runtime-spec / integration-tests` target layout.
- `audit-events/` under `contracts/` is a shared audit-event schema-adjacent layer; it is not a proof that canonical `sdk`, `runtime-spec`, or `wasm32-unknown-unknown` Host ABI/runtime integration is complete.
- Web4 currently uses a read-only API client by default; it falls back to local mock snapshots only when explicitly launched with `?mode=mock`, and write paths are not exposed by default.
- If you see `/api/v0/web4/*` references in docs, treat them as historical naming only; current frontend consumption is around:
  - `query-task`
  - `query-events`
  - `query-capability-audit`
  - `query-normalized-audit-events`

### Read-surface contract (important for integration)

- The following endpoints are the current minimal read contract:
  - `query-task/<task_id>`
  - `query-events/<task_id>?limit=<n>`
  - `query-capability-audit/<subject-or-token>`
  - `query-normalized-audit-events?source=<source>&eventType=<eventType>&cursor=<cursor>&limit=<n>`
- `query-task/<task_id>` prefers persisted state snapshots first, then replay over canonical node event history. Adapter fallback may only enrich `Committed`/`Revealed` views when persisted commit history exists.
- For `query-events/<task_id>`, adapter fallback is strictly bounded/deduplicated to recent commit/reveal tails; it must not invent pre-commit history.
- For durable indexer/archive replica planning, persist canonical node event streams rather than relying long-term on adapter fallback.
- Reference: [TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md](trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md) and [TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md](trillionnium/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_MATRIX_2026-04-03.md)
- These two documents freeze the **Day-1 minimum public read surface only**, not full durable-indexer/archival read-model readiness.
- `query-events/<task_id>` defaults to `100` and hard-caps at `500`; no assumption of infinite window.
- `query-events/<task_id>` currently accepts only one `limit` key. Unknown keys, duplicated `limit`, case variants (`Limit=`), empty values, or query smuggling are fail-closed.
- `query-capability-audit/<subject-or-token>` supports both capability token and subject DID.
- `query-normalized-audit-events` currently accepts only `source / eventType / cursor / limit`; unknown keys, repeated keys, case variants (`Limit=` / `Source=` / `eventtype=` / `Cursor=`), empty values, and smuggling are fail-closed.
- Paths with a single trailing slash are accepted for:
  - `query-task/<id>/`
  - `query-events/<id>/`
  - `query-capability-audit/<subject>/`
  - but **not** for `query-normalized-audit-events/` (currently exact path only).
- For `query-events/<id>/`, the `limit` query contract is unchanged: `?limit=<n>` still parses normally, default remains `100`, and the same fail-closed rules apply.
- All read endpoints remain fail-closed for extra segments, raw/encoded slash tricks, and query/fragment smuggling.

### Explorer scaffold (operator-facing)

Current explorer service in this repo is an operator-facing scaffold, not a production durable indexer.

Typical commands (run from repo root):

```bash
./trillionnium/scripts/v2/explorer_service_up.sh
./trillionnium/scripts/v2/explorer_service_status.sh
./trillionnium/scripts/v2/explorer_service_down.sh
```

Or from inside `trillionnium/`:

```bash
./scripts/v2/explorer_service_up.sh
./scripts/v2/explorer_service_status.sh
./scripts/v2/explorer_service_down.sh
```

- Service status defaults to `http://127.0.0.1:8090/healthz`.
- Environment overrides: `EXPLORER_HOST`, `EXPLORER_PORT`, or `EXPLORER_HEALTH_URL`.
- If `trillionnium/run/explorer-service/explorer-service.env` exists, the scripts load it automatically.
- For external exposure, prefer loopback-bound bind + reverse proxy.
- `explorer_service_status.sh` reports `pid_file`, `log_file`, `health_url`, and explicitly marks `service_mode=operator-facing-static-scaffold`, `production_ready=false`.
- Current scaffold intentionally keeps durable-read anchors fail-closed:
  - `ingestion_source`
  - `checkpoint_store`
  - `replay_start_anchor`
  - `retention_scope`
  - `archive_owner`
  - `lag_slo`
- In handoff notes, include flags such as:
  - `deployment_evidence_scope=placeholder-only`
  - `rank1_read_surface_blocker=still-open`
  - `durable_indexer_status=not-implemented-in-this-scaffold`
  - `durable_read_anchor_complete=false`

Only switch to durable handoff templates when all six durable-read anchors are truly implemented.

---

## License

MIT
