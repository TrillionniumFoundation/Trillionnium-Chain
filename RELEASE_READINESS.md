# TRNM Release Readiness

Updated date: 2026-08-01
Scope: A citation must record the remote URL, fetch UTC/result, branch, `HEAD`,
`refs/remotes/origin/main`, clean/dirty `git status --porcelain`, and this
document's SHA-256. Run `git fetch --prune origin main` first. If fetch or
authentication fails, label the remote baseline stale/unverified; never call a
cached tracking ref contemporaneous.

> This file is the active **release readiness truth source**.
> Release, RC, or handoff evidence is bound to the exact assessed tree above;
> uncommitted results must not be presented as an `origin/main` repository baseline.
> - `docs/archive/root-history/STATUS.md`: historical progression log / working journal, not used for current release determination.
> - `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`: scheduling board for development, not release truth.
> - `docs/archive/web4-history/GO_READY_EVIDENCE_WEB4_2026-03-03.md` and `docs/archive/web4-history/web4-fix-sequence-2026-03-04-evidence.md`: represent a historical fix/pass batch, not today's global release posture.

## Current Conclusion

**Conclusion: Not release-ready; do not claim external readiness.**

### 2026-07-28 canonical-runtime truth

- `CometBFT + trnm-consensus-app + trnm-runtime` is the sole production-candidate
  state-transition path. `trnm-chain-node`, `trnm-chain-validator`, `trnm-chain-cli`,
  and `trnm-sim` are frozen legacy harnesses. Their tests, benchmarks, or fault
  simulations are not evidence that the production candidate implements a feature.
- `trnm-finality-types` and `trnm-finality-verifier` are the supported minimal
  dependency boundary for receipt consumers. External services must not depend on
  the complete `trnm-node` package merely to verify finality.
- `trnm-consensus-app` is a CometBFT-backed public-testnet prototype. It now rejects
  unknown production payloads and executes typed account, sequential account nonce,
  gas/fee, task escrow, assignment, commit/reveal, paid consumption, challenge,
  resolution, settlement, deterministic deadline expiry, and fee-governance
  transitions through the pure
  `trnm-runtime` crate. A four-validator process gate now proves identical canonical
  objects, account nonces, issued supply, fee collection/distribution, terminal balances,
  block history, and AppHash while rejecting forced assignment, replay,
  over-gas, and unknown-payload transactions. AppHash v4 now uses a versioned
  JMT root with SQLite-backed point planning, ICS23 membership/non-membership
  queries, persisted pruning, and format-4 streaming SQLite snapshots. Persistent
  startup no longer materializes the object set or JMT. Snapshot chunks and their
  receive journal are synchronized incrementally, survive a process restart, and
  are validated against an exact canonical SQLite schema, latest-only reachable
  JMT closure, chain/signer bindings, and lifecycle authorization before install.
  Persistent nodes reject the memory-concatenating legacy format 3. A
  release-profile executable gate
  completed exactly 1,000,000 initial objects plus 1,000,000 updates across 200
  JMT versions in 142.5 seconds under a 5 GiB virtual-memory limit. Early/late
  update-batch P95 was 697/960 ms; pruning retained 64 versions while preserving
  the boundary/latest ICS23 proofs and latest root. Peak RSS was 4.44 GiB. This
  is an in-memory JMT algorithm/retention gate, not SQLite fsync, CometBFT block,
  or multi-host latency evidence. The persistent-store gate now emits report schema
  `trnm_apphash_v4_persistent_scale_report_v2` inside evidence schema
  `trnm_persistent_scale_evidence_v3`. It binds the configured row/byte pruning
  budgets, separates snapshot/maintenance/writer/SQLite retry causes, samples 32
  commit latencies, requires at least four samples while pruning remains pending,
  proves a deterministic real-writer yield, records adaptive budget changes, and
  requires exact restart plus resumable format-4 restore. A
  dirty-tree release-build smokes have completed exactly 10,000 objects plus
  10,000 updates with all report/resource assertions passing; they are explicitly
  single-process, single-host, outside canonical `FinalizeBlock`, not CometBFT
  end-to-end, and not million-gate evidence. Their working-directory artifacts
  were not attached to a durable evidence bundle and therefore are non-citable
  local diagnostics, not verifiable release evidence. A clean checked-out `HEAD`
  must rerun and retain the gate before any result is promoted. The earlier local formal 1M+1M attempt
  at `072270c39` produced an approximately 827 MiB normalized snapshot but exited
  137 during restore, leaving an invalid report; it is a capacity datapoint, not a
  pass. Snapshot validation now binds the manifest hash, semantic checks, and
  install backup to one private inode; requires canonical 4096-byte pages, zero
  freelist, exact file length and schema/JMT closure; and caps the accepted database,
  aggregate rows, and validation scratch space. These limits are the current
  state-sync operational envelope, not a consensus state-growth limit. Restore
  operators must reserve about 9 GiB of transient space for the maximum 4 GiB
  receive stage, 4 GiB private validation copy, and 1 GiB validation scratch,
  plus separate headroom for the live database, WAL, and VACUUM. If state
  grows beyond them, consensus can continue but format-4 snapshot production and
  restore fail closed until an explicit capacity upgrade. Million-object
  persistent-store restart/prune/restore latency therefore remains open. Local
  four-validator offline/rejoin, fresh-node ABCI state sync, deterministic proposal
  filtering, transactional SQLite-WAL delta persistence, and validator-lifecycle
  unit/crash-recovery gates pass. A six-node process fixture proves 4→5, 5→4,
  and one-key validator rotation, while rootless `3-1` and `2-2` partition gates
  prove stall/progress/heal safety. The four-validator fixture also injects
  one-shot process crashes during `ProcessProposal`, `FinalizeBlock`, and after
  durable SQLite commit but before the ABCI `Commit` response, then proves replay,
  SQLite-tip recovery, continued finalization, and app-hash convergence. Transport
  authentication, cross-host recovery, threshold governance, HSM/KMS, and soak
  evidence are still incomplete.
- The canonical runtime exposes a latest-committed-state `/simulate` ABCI query.
  It shares the exact gas/fee calculation with execution, returns a versioned
  response with stable error codes, and discards all proposed mutations. Focused
  tests prove simulation/CheckTx/finalized gas parity and unchanged height,
  AppHash, objects, nonces, and pending state. This is transaction simulation and
  fee estimation only; it is not an offline signer or secure key-custody solution.
- Bounded deterministic runtime model tests cover issued-supply conservation,
  sequential nonce/replay/gap rejection, failure immutability, and identical
  state/receipt/event replay. Two isolated `cargo-fuzz` targets exercise canonical
  transaction and signed-envelope public input boundaries. The checked-in fuzz
  job is a short integration smoke, not evidence of a long-running campaign or
  formal verification.
- Local supply-chain hardening pins Rust 1.95.0 and every GitHub Action to a full
  commit SHA, checks application, contract, and fuzz dependency graphs with
  `cargo-deny`, checks the frontend lock with `npm audit`, and freezes the legacy
  binary entrypoints and manifest. The wider no-new-legacy-capability rule is
  still review-enforced because canonical and legacy paths share library modules.
  `SECURITY.md` remains an unverified reporting-policy draft;
  private-reporting enablement, an external audit, SBOM/provenance, and long fuzz
  evidence remain open.
- The historical signed package is a frozen legacy-harness reproducibility
  artifact, `loopback-local-devnet`, `development_only=true`, and
  `public_mainnet_ready=false`; it is no longer built automatically.
- The authoritative feature-to-runtime matrix and Day-1 freeze are in
  `docs/architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`. Features not
  marked implemented in that matrix remain unimplemented regardless of legacy tests.
- This branch uses application version 4, store schema 4, and persistent snapshot
  format 4. Snapshot format 3 is restricted to the memory-only compatibility
  harness.
  It deliberately refuses in-place v3 root rewriting. The verified
  `trnm-v3-export-new-genesis` tool emits a review-only bundle for a different
  chain ID and leaves the old source untouched; operator review/signing and an
  actual new-genesis ceremony remain required.
- Transaction authentication remains a static authorized-signer allowlist; dynamic
  public account-key onboarding is not implemented.

The repo has useful local gates, reusable partial evidence packs, and front-end pre-release checks, but there are still active risks of truth-source drift.

Boundary clarification:
- `RELEASE_READINESS.md` answers the question "is this current repository snapshot currently expressible as release-ready / externally publishable?".
- `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` answers: if the goal is **public mainnet launch**, which P0/P1 blockers still remain.
- Therefore, a local RC rehearsal pass, full validator handoff evidence, or a single GO-ready sub-route cannot by itself be treated as public mainnet readiness.

Current major drift risks include:

1. `docs/archive/root-history/STATUS.md` still describes the 2026-02-21 state from a "releasable baseline" perspective, but that framing is now stale.
2. The root `README.md` historically pointed preflight scripts to root-level `scripts/*.sh`; those paths are no longer in use. They now live in `web4-frontend/scripts/`.
3. Web4 documentation saying GO-ready / PASS is historical evidence and cannot be interpreted as current, repository-wide release-ready status.
4. Legacy verifier PoC assets (`rust/verifier`, `scripts/run_rust_verifier_poc.sh`) are not present; documents implying an always-present in-repo verifier now overstate current capability.
5. Web4 current semantics are **readonly API client + explicit mock fallback**: the UI attempts readonly query path by default, and only falls back to local snapshots under explicit `?mode=mock`. Do not describe it as a purely static mock page, and do not describe it as a production write-enabled backend.
6. `/api/v0/web4/*` references are historical V0 naming. There is no corresponding Next.js route currently; effective read semantics come from `web4-frontend/lib/api-contract/*` and `web4-frontend/lib/dashboard/source.ts`.
7. Concurrency closeout and external comparisons are still in document-consolidation phase: `docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md` is the current bottleneck map and 8-week route entry, `docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md` is an external benchmark draft; both describe progress, not release proof.

## Component Status

### 1. Rust L1 / Mainchain
- **Status**: Development in progress. Many gate, replay, benchmark, and nightly scripts/documents exist.
- **Confirmed facts**: Release-related scripts such as `trillionnium/scripts/release_rc.sh` and `trillionnium/scripts/run_local_release_evidence.sh` are present.
- **Do not claim**: the repository as a whole is globally release-ready.

### 2. Web4 Frontend
- **Status**: Independent npm preflight chain exists. Frontend behavior is readonly query client with fail-closed handling; in dev/demo mode it can explicitly use mock fallback.
- **Confirmed facts**: `web4-frontend/package.json` contains `ci:check` / `release:preflight` / `release:ready`, which call scripts in `web4-frontend/scripts/`; `web4-frontend/lib/api-contract/client.ts` currently consumes `GET /query-task/:taskId`, `GET /query-events/:taskId`, and `GET /query-capability-audit/:subject`. The 2026-07-28 local clean-install gate passed dependency compatibility, audit with zero known vulnerabilities, lint, TypeScript, 201 unit/component tests, 83 contract tests, one real-browser Playwright E2E, and the Next.js production build.
- **Limitation**: Historical GO-ready docs exist; no implementation exists for `/api/v0/web4/*` inside this repo, so it is incorrect to characterize Web4 as broadly production-ready or as an in-repo dashboard API write backend.

### 3. Verifier / Sidecar
- **Status**: Legacy Rust verifier PoC core is not present in this repository.
- **Confirmed missing pieces**: `rust/verifier`, `scripts/run_rust_verifier_poc.sh`, and `docs/protocol/rust-verifier-poc.md` are currently absent.
- **Narrative boundary**: it is acceptable to describe this as "historical cross-check / evidence recording path", but not as an in-repo verifier subsystem currently complete.
- **For P1.3 closure assessment**: use `trillionnium/docs/release/TRNM_VERIFIER_DA_CHECKPOINT_SIDECAR_CLOSURE_2026-03-31.md` and evaluate deployable boundary, DA checkpoint linkage, failure taxonomy, and replay evidence. This is a closure checklist, not a release-ready proof.

## Documentation Usage Rules (truth-source hierarchy)

1. **Current release decision**: Start here with `RELEASE_READINESS.md`.
2. **Development planning / lane scheduling / next execution**: `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`.
3. **ZKP platform boundaries / backend abstraction / payload and error contracts**: `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`.
4. **Benchmark closeout method, unified outputs, micro-to-system bridge**: `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`.
5. **Current concurrency architecture, external comparison framing, and 8-week plan**:
   - Current bottleneck map and 8-week route: `docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md`
   - TRNM vs Solana vs Sui comparison framing: `docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md`
6. **Historical progress and milestones**: `docs/archive/root-history/STATUS.md`.
7. **Any web4/release fix batch outcome for a specific cycle**: corresponding files under `docs/archive/web4-history/*evidence*.md`.
8. **Subproject operational docs**:
   - Repository overview: `README.md`
   - Web4 subproject: `web4-frontend/README.md`
9. **RC / validator handoff operations**: `trillionnium/docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`.
   - Use when passing `testnet_preflight.sh`, `run_local_release_evidence.sh`, and `release_rc.sh` artifacts between operator / validator hands.
   - Scope: artifact path parsing, identity-field checks, replay/rollback references; **does not** replace this file's release conclusion.
10. **Public mainnet blocker interpretation / P0-P1 sequencing**: `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`.
   - Use when answering what remains for public mainnet, what is a launch blocker, and the minimum Day-1 trust scope.
   - Scope: closure matrix for mainnet, not equivalent to any single local RC run passing.
11. **Minimal mainnet observability pack and alert + incident handoff conventions**: `trillionnium/docs/runbooks/mainnet-observability-alerting-starter-pack.md`, plus oracle-specific guidance from `trillionnium/docs/runbooks/oracle-observability-alerts.md`.
   - Use for severity/signal/needs_replay/needs_rollback tags, minimal dashboard bundle, first-stop panel, and handoff replay/rollback pointers.
   - Scope: shared starter pack and on-call semantics, not observability P0 closure, and not full release readiness.
12. **Collapse 36-lane execution into a GO-NO-GO launch-distance panel**: `trillionnium/docs/release/TRNM_PUBLIC_MAINNET_GO_NO_GO_PANEL_2026-04-04.md`.
   - Use when answering how far current local execution is from public launch, which items are hard blockers, and what can move after Day-1.
   - Scope: status panel over current lane snapshot, not global release-ready proof.
13. **Classify MN01 residuals**: whether remaining hunks are unmerged work or already absorbed/superseded by mainline: `trillionnium/docs/release/TRNM_MN01_RESIDUAL_CLOSURE_2026-04-05.md`.
   - Use when deciding what in `lane/mn01-peer-bootstrap-topology` still requires manual absorption and why many `git cherry -v` plus signs are semantically mostly already covered by mainline.
   - Scope: lane residual closure; does not replace this file.
14. **Reassess public-mainnet distance from current local integrated main** (including unpushed local absorptions): `trillionnium/docs/release/TRNM_MAINNET_READINESS_REASSESSMENT_2026-04-05.md`.
   - Use when evaluating where local `main` currently sits relative to public launch and which blockers remain on the shortest path.
   - Scope: requires pair-citing local main and remote main commits; does not imply remote `origin/main` is already at same conclusion.
15. **Convert local integrated main residual distance into executable closing packages / exit criteria / evidence packets / first execution slice**: `trillionnium/docs/release/TRNM_MAINNET_CLOSURE_EXECUTION_BOARD_2026-04-05.md`.
   - Use to move from "what remains" to concrete closure packages and sequencing.
   - Scope: execution board, not a release conclusion.
16. **Prioritize Rank-1 shortest honest first slice (public read surface / indexer / explorer)**: `trillionnium/docs/release/TRNM_RANK1_FIRST_EXECUTION_SLICE_2026-04-05.md`.
   - Use to define what is already frozen, what is still non-binding, and how placeholder versus durable boundaries are decided in practice.
   - Scope: only the first slice; not Rank-1 closed, and does not claim durable indexer/historical read model/explorer backend completion.
17. **Decide durable boundary candidate direction for six durable-read anchors**: `trillionnium/docs/release/TRNM_RANK1_DURABLE_BOUNDARY_DECISION_MEMO_2026-04-05.md`.
   - Use when asking how to proceed from Rank-1 first slice and how to turn remaining placeholders into an implementation path.
   - Scope: decision memo only; not a proof of closure.
18. **Convert durable-boundary direction into implementation design package** (schema / ingest loop / replay bootstrap / lag formula / retained-surface materialization): `trillionnium/docs/release/TRNM_RANK1_IMPLEMENTATION_DESIGN_PACKET_2026-04-05.md`.
   - Use for implementation approach from rpc-pull + sqlite + genesis replay to concrete MVP; does not mean Rank-1 is closed.

## RC Rehearsal Evidence Template (non-release)

> Goal: run rollback-friendly RC readiness rehearsals only; no release tagging or publishing.

- **CI / gate command**: record the exact command with exit code for each run. Prefer a deterministic prefix such as `env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200`.
  - Rust example: `env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200 cargo test -p trnm-rpc --test reliability_persistent_smoke -- --nocapture`
- **Deterministic rerun**: run each critical gate at least twice with identical command and environment; single green runs can hide flake.
- **Replay evidence**: persist both input snapshot and output summary location, e.g. `trillionnium/run/health/evidence-<timestamp>/`, and include UTC timestamp with `date -u +%Y-%m-%dT%H:%M:%SZ`.
- **Replay command source**: if using `run_local_release_evidence.sh`, cite `replay_command=` from `summary.txt` directly. Do not rewrite it manually without the deterministic wrappers.
- **Environment interpretation**: fields under `env_*` in `summary.txt` reflect live shell environment; authoritative replay baseline is `replay_env_*`.
- **challenge reexec fields**: when citing challenge reexec-related values, preserve both `replay_env_trnm_challenge_reexec_entry=` and `challenge_reexec_entry=` verbatim, including `<entry_not_found>` if unresolved.
- **RC manifest boundary**: if citing `manifest.txt` generated by `trillionnium/scripts/release_rc.sh`, include `truth_source`, `historical_evidence_only=true`, and `evidence_scope` together; do not present gate outputs as current release proof.
- **Artifact identity consistency**: when comparing `summary.txt` and `manifest.txt`, verify identity fields match exactly (`git_branch`, `git_head`, `git_head_state`, `git_worktree_path`, `git_worktree_branch_ref`, `git_expected_worktree_branch_ref`, `git_worktree_branch_ref_match`). `git_worktree_branch_ref_match` must be true.
- **No false binding by timestamp**: a latest path such as `run/health/evidence-*` is not sufficient proof of lane identity; check worktree path/branch against ticket-specified values.
- **Prefer fail-closed helpers**: for handoff and audit, use `./trillionnium/scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root <ticket-path> --expected-branch-ref <ticket-branch>` (or from `trillionnium/` as `./scripts/v2/extract_release_handoff_fields.sh ...`). This helper accepts short branch names or full refs.
- **Record helper output**: always tee helper output to an auditable file (for example `trillionnium/run/preflight/handoff-fields-<timestamp>.txt`) and cite from that artifact.
- **Lane binding from ticket values**: lane validation must be run with ticket-provided `--expected-worktree-root` and `--expected-branch-ref` via `verify_lane_worktree.sh` before handoff; do not backfill from current shell assumptions.
- **Rollback command**: every run should include a single rollback line in notes, e.g. `git revert <commit>` or `git checkout -- <file>` for docs.
- **Root-cause tags**: use consistent labels on failure (recommended: `CI_FLAKE`, `ENV_DRIFT`, `DOC_DRIFT`, `MISSING_FIXTURE`, `NON_DETERMINISTIC_TEST`).

Recommended release update annotation in each commit note: include fixed fields `gate`, `evidence`, `rollback`, `root_cause` for automation.

## Remaining deferred items / not addressed in this rewrite

1. No full-repo release gate rerun was executed in this documentation pass.
2. Not every historical document was rewritten; only docs most likely to misstate current readiness were normalized to reduce external confusion.
3. No code or release script behavior changed; this pass only aligned truth-source and documentation framing.
