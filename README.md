# Trillionnium Chain (TRNM)

**TRNM** is a Rust-native Layer 1 focused on **Decentralized AI Compute** (PoCO).

- Active mainline: `trillionnium/`
- Historical status/archive docs live under `docs/archive/`
- Current consensus target: deterministic PoCO-BFT v0; see
  `docs/architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`
- CometBFT is retained as a development differential oracle, not the target
  production finality authority.

---

## 1) Project Positioning

TRNM is a Rust L1 protocol for task-based AI compute settlement and verification. Its core design goals are:

- **PoCO state machine** for task lifecycle: create → commit → reveal → challenge → resolve
- **High-concurrency execution** with conflict detection and grouped scheduling
- **Auditable events + stable interfaces** for integration, replay, governance, and operations
- **Worker Agent + CLI** legacy local adapter loop for retry/replay evidence;
  canonical worker-to-PoCO broadcast/query is still an open integration boundary
- **BL09 retirement-prep wording**: the retained `trnm-pouw` crate name and any residual PoUW fields should be read as migration-era compatibility or provenance/audit evidence, not as ongoing payout authority or a default work-unit payout path

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
│   │   ├── trnm-protocol
│   │   ├── trnm-runtime
│   │   ├── trnm-consensus-types
│   │   ├── trnm-consensus-core
│   │   ├── trnm-consensus-sim
│   │   ├── trnm-consensus-app
│   │   └── trnm-bridge-poc
│   ├── configs/
│   ├── scripts/
│   └── run/
├── web4-frontend/                  # Web4 frontend (Next.js + Vitest + Playwright)
├── scripts/                        # Repo-level CI/automation scripts
├── docs/                           # Architecture, protocol, runbooks, reports, and historical archive docs
├── contracts/                      # Rust-native external contracts subtree (4-crate MVP, not full runtime-spec/sdk closure)
├── config/                         # Policy and alerting config
├── examples/                       # SDK and demo examples
├── OPERATIONS.md                   # Operator-facing handbook
└── RELEASE_READINESS.md            # Current release truth source
```

---

## 3) Core Modules

### Rust mainline (`trillionnium/crates`)

- `trnm-node`: legacy harness package containing the bespoke `trnm-chain-node`,
  `trnm-chain-validator`, `trnm-chain-cli`, and `trnm-sim` binaries; these paths
  are frozen for compatibility and are not production-runtime evidence
- `trnm-finality-types` / `trnm-finality-verifier`: node-independent finality wire
  types and receipt verification for external consumers
- `trnm-protocol` / `trnm-runtime`: the canonical typed transaction protocol and
  pure deterministic state transition for accounts, fees, task escrow, PoCO
  consumption settlement, challenge, and resolution
- `trnm-consensus-types`: network- and storage-independent PoCO-BFT v0 type
  scaffold for canonical signing inputs, certificates, handoff, and evidence;
  remaining conformance gaps are release-blocking and tracked explicitly
- `trnm-consensus-core`: deterministic PoCO-BFT state-machine prototype. It has no
  sockets, database, filesystem, wall-clock, or signer-device dependency and
  requires persistence acknowledgement before requesting a signature
- `trnm-consensus-safety-store`: standalone Linux SQLite SafetyState journal.
  Its concrete, non-cloneable native-invalid exact-readback token can be issued
  only after complete head validation; the token exposes read-only facts and
  grants no callback, Core, or general application transition authority by
  itself. G1c accepts it only as one required provenance input to the bounded
  application recovery transition, together with the pinned local binding
  manifest and the exact existing `Delivered`/`Acked` row
- `trnm-consensus-signer-journal`: append-only canonical sign-intent/signature
  journal with an injected external monotonic-watermark contract; the external
  production watermark/remote signer remains unwired
- `trnm-consensus-sim`: deterministic, replayable fault simulator for the pure
  core; it is test evidence, not a deployed network or production node
- `trnm-consensus-app`: the preserved CometBFT development oracle and runtime
  integration fixture, using ABCI++ with typed canonical transactions,
  fail-closed unknown payloads,
  account sequence nonces, gas/fees, indexed execution events,
  replay-safe app-hash v3, committed validator lifecycle, SQLite-WAL delta
  persistence, stable empty-block state roots, local fresh-node state sync,
  a four-validator funded PoCO/challenge vertical slice with value-conservation
  and negative resource/replay checks, four-node proposal/vote/finalize/commit
  crash recovery, six-node validator
  rotation, and rootless partition-safety evidence
- `trnm-poco-node`: non-legacy, fail-closed PoCO host scaffold. Its default-build
  G1f ordinary owner now uniquely holds Core, SafetyStore, signer journal, and
  one injected exact-idempotent producer for a bounded local-timeout path:
  `PersistSafetyState -> StorageAck -> CanonicalSignIntentV0 -> sign journal ->
  SignatureReady -> fingerprint-bound outbound`. A restart replays the exact
  persisted timeout signature without invoking the producer again. A
  required-feature local Linux matrix now kills and reaps a direct child with
  SIGKILL at six bounded userspace points from SafetyStore readback through
  verified typed Broadcast, then compares the full fingerprint/revision/root/
  TimeoutVote/signature identity across two fresh official-host recovery
  processes. Vote signing, a production producer/HSM, pacemaker, transport,
  application execution, and a general effect driver remain absent. This is
  not power-loss, hardware-fsync, wire-byte delivery, or whole-namespace
  rollback evidence. The separate G1c
  recovery owner performs only the bounded three-store joins obligation +
  `CallbackPending`, obligation + `Delivered`, completion + `Delivered`, and
  completion + `Acked`. G1e validation-recovery SIGKILL is archive-only. It is
  non-buildable in the active Cargo graph. Its tracked helper and integration
  test preserve the former four-state design, but they are not node artifacts,
  active native-CI tests, or current readiness evidence
- `trnm-state`: versioned state store and `state_root`
- `trnm-pouw`: PoCO task state machine and validation logic (legacy crate name retained during migration; do not read it as current payout-authority wording)
- `trnm-executor`: conflict detection and concurrent scheduling strategy
- `trnm-mempool`: transaction pool and admission/packaging
- `trnm-rpc`: RPC service and stable query APIs
- `trnm-worker-agent`: legacy worker execution and local adapter-state path;
  it is not yet wired to canonical PoCO receipt broadcast/query
- `trnm-cli`: native CLI for tx/query operations
- `trnm-bench`: benchmarking and performance tooling
- `trnm-types`: shared protocol types
- `trnm-bridge-poc`: bridge proof-of-concept integration

The PoCO-BFT v0 architecture target is maintained in
`docs/architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`. The older Day-1
runtime table in `docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`
remains useful evidence for the reusable runtime/JMT boundary, but its CometBFT
production-authority decision is superseded. Bridge, external contracts, and
full ZK platform work remain outside the frozen PoCO-BFT v0 scope.

The G1c validation-recovery slice is intentionally narrow. Ordinary
`Core::recover` still rejects every obligation-bearing SafetyState; a separate
inert session admits exactly one durable obligation and only an independently
reconciled `DeterministicallyInvalid` application result. The application
recovery owner opens an existing schema-v8 journal and supports only
`CallbackPending`, `Delivered`, and `Acked`; `Reserved`, `Evaluated`, `Applied`,
`Valid`, and `Unavailable` remain fail-closed. A fresh executor, BlockId-keyed
speculative overlay, ordered finalization, general effect driver and network,
state sync, the complete production crash matrix, and whole-namespace rollback
protection remain release blockers. The tracked historical G1e source describes
an authentic feature-only fixture that seeds `O+P`; the official existing-only
host then authenticates and observes that boundary and drives the real
`P -> D -> C -> K` transitions. That archived design covered sixteen SIGKILL
checkpoints:
`O+P`, `O+D`, `C+D`, and `C+K` across both routes and both supported
deterministic-invalid reasons. In that historical record, `O+P` was
recovery-from-preseeded-state evidence, while the other three states were
reached by official host transitions. Its former harness required a fresh
process to authenticate and
recover the exact journals after each kill, and the parent compared the
complete `ValidationId`, completion
revision, and signer-watermark tuple across checkpoint, recovery, and final
verification processes. Independent same-process file-adapter tests cover live-owner
exclusion, stale CAS, journal switching, checksum corruption, and trailing
bytes. That was historical local Linux process-termination evidence only; it
was not power-loss, host-reboot, device-write-cache, or hardware-fsync
evidence. The active Cargo manifest no longer registers its
filesystem watermark, helper, or integration-test target; the tracked files
are archive source only and are excluded from the `--no-default-features`
development-library artifact. The application recovery
facade now excludes ordinary
shared opens with an exclusive sidecar lock, pins the owner PID plus canonical
parent/lock/main-database identities, and requires a create-once checksummed
manifest that durably binds the designated Safety journal/profile. Recovery
also rejects non-owner or group/world-writable parent, database, lock,
manifest, and existing WAL/SHM components; the three store parents may not be
equal or nested. This remains a local Linux boundary: WAL/SHM inodes are
SQLite-managed rather than independently pinned, and no hostile same-EUID,
power-loss, or complete production kill campaign is certified.

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

- Rust 1.95.0 (exactly pinned by `rust-toolchain.toml` and CI)
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

### 4.5 External contracts subtree smoke

```bash
cargo test --manifest-path contracts/Cargo.toml
```

This validates the current `contracts/` MVP workspace only, which today contains `settlement-vault/`, `bridge-relay/`, `governance-guard/`, and `audit-events/`. It should not be read as proof that the target `sdk/`, `runtime-spec/`, `integration-tests/`, or canonical Host ABI/runtime closure already exist in-tree.

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
# Hermetic legacy worker adapter/state-machine regressions. These exercise
# retry, replay, nonce and acknowledgement handling; they are not evidence of
# a real chain broadcast.
./scripts/v2/run_worker_receipt_gates.sh

# Active PoCO CLI surface and retired-command cutover
./scripts/v2/worker_poco_cli_cutover_gate.sh
```

The active native PoCO CLI intentionally does not implement the legacy worker
`commit-result` / `reveal-result` protocol. The historical
`run_worker_receipt_gates_real_cli.sh` entrypoint is only for an explicitly
configured external compatibility adapter with real RPC and key material; it
is not part of offline CI and is not proof that worker-to-PoCO broadcast/query
is complete. That production path remains open until the worker submission
schema is migrated to the canonical PoCO receipt model.

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
- Unified development scheduling: historical planning boards have existed under archived docs, but if a referenced planning-board file is absent in this checkout, use repository docs under `docs/`, `trillionnium/docs/`, and the subproject READMEs as the live execution entrypoints instead.
- External benchmark comparison: [docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md](docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md)
- Concurrency bottleneck map + 8-week roadmap: if an older report is referenced from `RELEASE_READINESS.md` but not present in this checkout, treat it as historical only and do not cite it as current local truth.
- Web4 platform overview: if an older master-planning file is absent in this checkout, treat `RELEASE_READINESS.md`, `docs/reports/TRNM_WEB4_PLATFORM_SCORECARD_2026-03-31.md`, `web4-frontend/docs/README.md`, and `web4-frontend/README.md` as the current Web4 truth-source entrypoints.
- Rust-native external contracts baseline architecture: [trillionnium/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md](trillionnium/docs/protocol/external-contracts-rust/RUST_NATIVE_EXTERNAL_CONTRACTS_ARCH_2026-03-05.md)
- `contracts/` status and boundaries: [contracts/README.md](contracts/README.md)
- Historical path note for this perimeter: if an older prompt/doc still says `trillionnium-rust/docs/...` or `contracts-rust/...`, treat that as drift only. The current in-tree truth paths are `trillionnium/docs/...` and `contracts/...`.
- PoCO mechanism (challenge-economics / PoUW minimal packet): [trillionnium/docs/challenge-economics-minimal.md](trillionnium/docs/challenge-economics-minimal.md)
- A2A adapter contract: [docs/agent/a2a_adapter_contract_v1.md](docs/agent/a2a_adapter_contract_v1.md)
- MCP adapter contract: [docs/agent/mcp_adapter_contract_v1.md](docs/agent/mcp_adapter_contract_v1.md)
- Operations handbook: [OPERATIONS.md](OPERATIONS.md)
- OpenClaw ops micro-runbook: [docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md](docs/development/OPENCLAW_OPS_MICRO_RUNBOOK.md)
- Web4 frontend overview / quickstart: [web4-frontend/README.md](web4-frontend/README.md)
- Web4 documentation center (primary docs entrypoint for operator/developer guidance):
  - [web4-frontend/docs/README.md](web4-frontend/docs/README.md)
  - [web4-frontend/docs/developer-guide.md](web4-frontend/docs/developer-guide.md)
  - [web4-frontend/docs/api-contract.md](web4-frontend/docs/api-contract.md)
  - [web4-frontend/docs/testing-ci.md](web4-frontend/docs/testing-ci.md)
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
- Historical/archive material in this repo currently lives under `docs/archive/`; do not assume a top-level `legacy/` directory exists in every snapshot.
- Whether the project is currently **release-ready** is defined by [RELEASE_READINESS.md](RELEASE_READINESS.md); historical evidence documents are not automatically equivalent to live state.
- `contracts/` is an **independent Rust-native external-contract subtree / MVP contract scaffolding**. Today it contains 4 landed crates: `settlement-vault/`, `bridge-relay/`, `governance-guard/`, and `audit-events/`.
- `contracts/` is **not yet** the full `sdk / runtime-spec / integration-tests` target layout, and its current crates should not be described as completed Host ABI/runtime integration.
- `audit-events/` under `contracts/` is a shared audit-event schema-adjacent layer; it is not a proof that canonical `sdk`, `runtime-spec`, or `wasm32-unknown-unknown` Host ABI/runtime integration is complete.
- Presence of `contracts/` does **not** by itself move external contracts into Day-1 mainnet minimum scope; that boundary still follows `RELEASE_READINESS.md` plus `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`.
- When validating or citing this perimeter, prefer current-tree paths and commands, for example `cargo test --manifest-path contracts/Cargo.toml`; do not treat historical `contracts-rust/Cargo.toml` references as live workspace truth.
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
- Environment overrides: `EXPLORER_HOST`, `EXPLORER_PORT`, `EXPLORER_PUBLIC_BASE_URL`, `EXPLORER_HEALTH_URL`, and `EXPLORER_RPC_BASE_URL`.
- If `trillionnium/run/explorer-service/explorer-service.env` exists, the scripts load it automatically and preserve it as the operator-local source of truth across `up` / `status` / `down`.
- For external exposure, prefer loopback-bound bind + reverse proxy, and keep the emitted `local_health_url` as the local liveness target even when `public_base_url` points at a proxy-facing URL.
- `explorer_service_status.sh` reports `pid_file`, `log_file`, `public_base_url`, `health_url`, `local_health_url`, `rpc_base_url`, and explicitly marks `service_mode=operator-facing-static-scaffold`, `production_ready=false`.
- To capture one deterministic operator handoff packet for this scaffold, use:

```bash
./trillionnium/scripts/v2/capture_explorer_scaffold_handoff.sh
```

- That helper is intentionally **placeholder-only**. It preserves blocker markers such as `deployment_evidence_scope=placeholder-only`, `rank1_read_surface_blocker=still-open`, and `durable_indexer_status=not-implemented-in-this-scaffold`, and it rejects drift if fetched `index.json` no longer matches the scaffold contract.
- The emitted `summary.txt` is also a template-boundary packet, not just a file list. Reuse `template_selection`, `durable_template_allowed`, `durable_template_rejection_reason`, and every `truth_source_*` line verbatim instead of paraphrasing the scaffold into a durable-service handoff.
- Build the packet from `explorer_service_status.sh` output first, then reuse the emitted `index_url`, `health_url`, and `local_health_url` instead of hand-typing proxy/local URLs from shell memory. If you also fetch a reverse-proxy/public URL, attach it as separate evidence rather than replacing the local status-driven proof.
- When the public URL and local bind target differ, preserve the emitted `local_index_url` and `local_index_fetch_command` from `summary.txt` too. Do not reconstruct the local `/index.json` path by editing the public URL by hand.
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
- Use `trillionnium/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` for this scaffold path.
- Operator bring-up / reverse-proxy / systemd details live in `trillionnium/docs/runbooks/explorer-service-scaffold.md`; use that runbook to keep `health_url` and `local_health_url` aligned with the same deployed instance you hand off.
- Do **not** switch to `TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md` until all six durable-read anchors exist, replay/restore/lag evidence is attached in the same packet, and `summary.txt` reports `durable_template_allowed=true`.
- When the lane moves beyond placeholder scaffold work, the next implementation boundary is `trillionnium/docs/release/TRNM_RANK1_IMPLEMENTATION_DESIGN_PACKET_2026-04-05.md`, which defines the durable indexer/read-model path rather than more scaffold polish.

Only switch to durable handoff templates when all six durable-read anchors are truly implemented.

---

## License

MIT
