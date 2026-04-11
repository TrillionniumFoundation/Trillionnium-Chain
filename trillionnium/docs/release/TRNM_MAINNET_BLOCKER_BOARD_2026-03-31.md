# TRNM Mainnet Blocker Board (2026-03-31)

## Truth-source snapshot

- Repository snapshot evaluated: `origin/main = 8ff9f1fe45bdf3f027bce7d86ae51394c3df5d86`
- Companion truth sources:
  - `RELEASE_READINESS.md`
  - `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
  - `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`

## Headline judgment

**Judgment: still NOT ready for a public mainnet claim.**

However, one previously major meta-blocker is now closed:

> lane output has already been absorbed into `main`, and `origin` now only retains `main`.

So the project is no longer blocked by fragmented lane execution.
It is now blocked by the **remaining production-perimeter closure** around the integrated mainline.

## What changed since the 2026-03-26 gap matrix

The 2026-03-26 gap matrix remains the correct public-mainnet taxonomy, but the current situation is more specific:

- the repository is now a **single integrated mainline**, not a lane-ahead staging forest;
- local lane worktrees and branches have been cleaned and removed;
- the current blocker set should therefore no longer include `lane -> main integration`.

The remaining launch distance is best described as:

- **6 public-mainnet P0 blockers**
- **1 integrated prelaunch rehearsal / GO-NO-GO package**
- plus **3 optional P1 packages** if day-1 scope includes oracle / bridge / verifier productization

## Priority order (current mainline)

### Rank 1 — P0: Explorer / indexer / stable read-model

**Why this is still the hardest blocker**

TRNM still lacks a clearly closed public read surface.
The chain kernel can execute, but a public network also needs stable retrieval, indexing, and historical read semantics.

**What already exists**
- stronger RPC/query work than before the lane merge
- more query metering / health / reporting structure on main
- evidence that this area received substantial lane attention

**What is still missing**
- durable indexer boundary
- historical read model
- stable explorer backend/API
- archive/read replica strategy
- defined production query SLOs

**Exit criteria**
- one documented minimum public read surface
- one durable indexer pipeline
- one explicit historical-query/storage policy
- one operator-facing deployment path for explorer/indexer

**Next actions**
1. define minimum Day-1 read API surface
2. choose indexer persistence model and replay source
3. produce one explorer/indexer deployment/runbook draft

---

### Rank 2 — P0: Secure wallet / signer / keystore

**Why it remains blocking**

Current CLI/signer flows are stronger than before, but still not sufficient to justify a public-mainnet signer story.

**What already exists**
- `trnm-cli`
- wallet/query/tx MVP path
- stronger hash/surface guardrails than earlier snapshots

**What is still missing**
- secure keystore model
- offline signing path
- remote signer / HSM / multisig posture
- key rotation and compromise response
- operator-safe signing UX and runbook

**Exit criteria**
- one approved key-management model
- one offline signing path that actually fits operator workflow
- one rotation / compromise SOP
- one signer safety checklist attached to launch packet

**Next actions**
1. freeze signer threat model for Day-1
2. pick keystore/offline-signing architecture
3. write rotation / compromised-key runbook

---

### Rank 3 — P0: Real network formation / peer sync / join-rejoin

**Why it remains blocking**

The chain runtime is much stronger than an empty prototype, but a public chain still requires credible public-network semantics.

**What already exists**
- stronger node/recovery/state-sync related code and tests than before the merge
- WAL / checkpoint / recovery closure improved on main

**What is still missing**
- peer discovery / bootstrap peer management
- public-network sync expectations
- join/rejoin / lagging node acceptance criteria
- network-level abuse/backpressure handling
- operator-visible sync diagnostics for real deployment

**Exit criteria**
- one explicit bootstrap/join/rejoin model
- one sync/catch-up acceptance matrix
- one failure/lag/operator diagnosis flow
- one realistic multi-node network formation rehearsal

**Next actions**
1. define peer/bootstrap topology for Day-1
2. write join/rejoin acceptance table
3. run and record one multi-node sync/catch-up rehearsal

---

### Rank 4 — Launch gate package: Integrated prelaunch rehearsal + evidence + GO/NOGO

**Why this is its own package**

Even if all code-adjacent P0 items improve, TRNM still cannot claim public-mainnet readiness without a full-chain rehearsal package on the integrated mainline.

**What already exists**
- `RELEASE_READINESS.md`
- RC/rehearsal/handoff documentation
- local evidence and release scripts
- cleaner artifact discipline than earlier snapshots

**What is still missing**
- one integrated prelaunch rehearsal using the current mainline
- one path-resolved evidence bundle suitable for launch review
- one final GO / CONDITIONAL GO / NO-GO document
- one rollback drill attached to the same decision packet

**Exit criteria**
- full prelaunch rehearsal green on current `origin/main`
- artifact identities consistent across summary/manifest
- rollback command explicitly preserved
- signed operator decision packet

**Next actions**
1. define rehearsal scope against current `origin/main`
2. run full rehearsal with path-resolved evidence bundle
3. produce formal GO/NOGO memo

---

### Rank 5 — P0: Unified observability / alerting / SRE plane

**Why it remains blocking**

Metrics and health signals exist, but not yet as one clear production observability plane.

**What already exists**
- richer health/query/metering surfaces than earlier snapshots
- more runbook and observability-oriented work on main
- some replay/recovery visibility improvements

**What is still missing**
- unified metrics contract across node/rpc/worker/oracle/bridge
- dashboards
- alert thresholds and severity conventions
- incident labeling / attribution loop
- operator-first observability bundle

**Exit criteria**
- one metrics contract
- one dashboard pack
- one alert rules pack
- one incident workflow connecting metrics to replay/evidence

**Next actions**
1. freeze metric names and alert dimensions
2. define minimal dashboard and alert set
3. connect observability outputs to operator runbooks

---

### Rank 6 — P0: Economics / anti-spam / fee boundary freeze

**Why it remains blocking**

This is now less a “missing code” problem than a “launch freeze” problem.
The codebase has meaningful anti-spam / QoS / sponsor / challenge-bond work, but launch economics still need a hard public freeze.

**What already exists**
- significant mempool / anti-spam / fairness work on main
- economics freeze helper doc already exists

**What is still missing**
- final ingress class split
- sponsor boundary and caps
- retention pricing rule
- anti-spam floor / fee floor / admission floor
- authority/timelock for prelaunch changes

**Exit criteria**
- explicit Day-1 economics tuple frozen
- adversarial spam/fairness rehearsal run once against that tuple
- operator/public wording aligned with actual admission rules
- launch packet cites at least one green admission-side gate, one green retention-side gate, and the compile-slice integrity check

**Evidence anchors for the launch packet**
- admission boundary hard-stop: `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q`
- sponsor borrowed-slot discipline: `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q`
- sponsor revocation / drain-only duplicate retention: `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool hard_stop_idle_pop_preserves_restored_duplicate_metadata -q`
- anti-spam floor / sustained-load admission boundary: `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool non_reserve_only_normal_never_borrows_when_no_critical_headroom_remains -q`
- retention timing freeze after challenge: `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -q`
- retention restore/canonicalization companion gate: `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q`
- tuple integrity compile slice: `cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q`

**Next actions**
1. freeze ingress/sponsor/retention tuple
2. run one spam/fairness rehearsal against frozen tuple and capture the admission + retention companion gates above
3. attach freeze decision to launch packet

---

### Rank 7 — P0: Validator / operator lifecycle

**Why it is still P0**

A public chain is an operator system, not only a binary and a test suite.
This area improved meaningfully, but is still not fully closed as a public-mainnet operator lifecycle.

**What already exists**
- stronger bootstrap / preflight / rollback / handoff documentation
- validator bootstrap/rebootstrap runbook coverage better than before

**What is still missing**
- signed/public validator ceremony model
- validator replacement / rotation workflow
- disaster-recovery rebuild evidence
- upgrade/rollback drill as operator procedure, not only scripts

**Exit criteria**
- explicit validator lifecycle SOP
- operator ceremony/replacement flow
- one DR rebuild drill with evidence
- one upgrade/rollback drill using current mainline

**Next actions**
1. define validator ceremony and replacement flow
2. run one DR rebuild exercise
3. attach operator lifecycle pack to rehearsal packet

---

## Optional P1 packages (only if included in Day-1 scope)

### P1.1 Oracle online subsystem
Becomes P0 if day-1 positioning depends on oracle-backed features.

### P1.2 Bridge productionization
The crate is still honestly named `trnm-bridge-poc`; keep it P1 unless bridge is part of the public Day-1 promise.
For the current bridge settlement boundary and operator-facing audit tuple, pair this board with `docs/release/TRNM_BRIDGE_SETTLEMENT_AUDIT_NOTE_2026-04-02.md` so replay reviews cite the frozen `phase` / heartbeat / confirm evidence fields instead of ad-hoc log phrasing.

### P1.3 Verifier / DA witness / sidecar productization
Becomes P0 only if mainnet Day-1 positioning requires verifier-backed external proof serving.

## Current recommended closure sequence

1. public read surface / indexer
2. signer / keystore / offline signing
3. network formation / sync / join-rejoin
4. economics / anti-spam freeze
5. observability / alerts / SRE plane
6. validator/operator lifecycle
7. integrated rehearsal / evidence / GO-NOGO packet

If oracle / bridge / verifier are in Day-1 scope, insert them before the final GO/NOGO rehearsal.

## Practical use of this blocker board

Use this file as the **current blocker ordering memo**.
Use `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` as the deeper taxonomy.
Use `RELEASE_READINESS.md` as the canonical answer to whether the repository is already release-ready.

For the economics-specific blocker, pair this file with:
- `docs/release/TRNM_MAINNET_ECONOMICS_FREEZE_HELPER_2026-03-27.md`

## Bottom line

TRNM is materially closer to a credible public-mainnet story than it was before lane closure.
But the honest statement is still:

> **integrated mainline, not fragmented — yet still not public-mainnet ready until the remaining production P0 blockers and rehearsal packet are closed.**
