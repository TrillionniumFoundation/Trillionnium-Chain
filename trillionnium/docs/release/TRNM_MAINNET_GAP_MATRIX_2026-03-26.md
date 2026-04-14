# TRNM Mainnet Gap Matrix (2026-03-26)

> BL09 retirement-prep note: references in this gap matrix to `trnm-pouw`, PoUW state-machine surfaces, or retained challenge/resolve evidence should be read as migration-era compatibility or provenance / audit evidence only. They should not be interpreted as ongoing payout authority or as reauthorizing a default work-unit payout path. Where payout/default-settlement authority is discussed, PoCO settlement anchors remain the intended default path once promoted.

## Goal

Turn the current "what is still missing before public mainnet" discussion into a **single actionable gap matrix**.

This document is intentionally practical.
It does **not** claim TRNM is mainnet-ready.
It defines:

1. what already exists,
2. what is still missing,
3. which gaps are true **P0 launch blockers**,
4. and what the next 4-week closing sequence should be.

---

## Current headline judgment

TRNM currently looks much closer to:

> **stage-1 internal devnet / RC-prep**

than to:

> **public mainnet launch candidate**

Reason:
- core execution/state/task lifecycle machinery exists,
- local devnet / replay / evidence / smoke infrastructure exists,
- but the outer production perimeter is still incomplete.

That perimeter includes:
- real network formation and sync,
- validator/operator lifecycle tooling,
- secure wallet/signer path,
- explorer/indexer/read-model,
- unified observability/alerting,
- and release-grade economics / anti-spam policy freeze.

## Evidence boundary (RC / rehearsal / local proof)

RC rehearsal success, validator handoff completeness, or local release-evidence PASS are **supporting evidence only**.
They do **not** collapse public-mainnet P0 blockers by themselves.

In particular:
- `RELEASE_READINESS.md` answers whether the current repository snapshot should be described as release-ready.
- `TRNM_VALIDATOR_RELEASE_HANDOFF.md` answers how an operator should verify branch/worktree identity, preserve artifacts, and decide GO / CONDITIONAL GO / NO-GO for a rehearsal.
- `TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` answers what still blocks a **public mainnet claim**.

Interpretation rule:
- local `testnet_preflight.sh` PASS, `run_local_release_evidence.sh` PASS, or `release_rc.sh` PASS can prove that a branch is reproducible enough for an RC rehearsal;
- they cannot by themselves prove that peer formation/sync, validator lifecycle, secure signer path, stable explorer/indexer, unified observability, and launch economics are closed for public mainnet.

### RC evidence integrity minimum checklist

Before anyone upgrades an RC rehearsal from "useful local evidence" to "serious launch decision input", require all of the following together:
- the assigned worktree path and branch ref from the lane prompt / release ticket, recorded before any release script runs
- a fail-closed preflight run of `./scripts/v2/verify_lane_worktree.sh --expected-worktree-root <lane-worktree> --expected-branch-ref <lane-branch-ref>` using the ticket-assigned values directly (the branch argument may be either a short branch name like `lane/foo` or a full ref like `refs/heads/lane/foo`), rather than first inferring values from the current shell and then reusing those inferred values as the expectation
- a path-resolved `summary.txt` from `run/health/evidence-*`
- a path-resolved `manifest.txt` from `release/rc-*`
- matching `git_branch=`, `git_head=`, `git_head_state=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, and `git_worktree_branch_ref_match=` across those artifacts
- preserved `git_status_summary=clean` and generated timestamps next to those identity fields, so operators can prove the rehearsal came from a clean tree and quote the exact artifact generation moment instead of relying on shell memory
- a direct comparison showing the artifact `git_worktree_path=` / `git_worktree_branch_ref=` also match the lane-assigned path/ref, with `git_expected_worktree_branch_ref=` preserving the ticket-assigned target and `git_worktree_branch_ref_match=true` required instead of treated as a soft warning
- preserved `truth_source=`, `historical_evidence_only=`, and `evidence_scope=` fields next to the quoted PASS/GO language
- verbatim `rollback_command=` and `replay_command=` copied from the generated artifact, not rewritten from shell memory

Fail-closed rule:
- if either artifact path is unresolved, or any of the identity/truth-source fields drift across artifacts, treat the rehearsal as **evidence-incomplete** rather than "probably fine"
- prefer `./scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root <lane-worktree> --expected-branch-ref <lane-branch-ref>` (the branch argument may be either a short branch name like `lane/foo` or a full ref like `refs/heads/lane/foo`) so this comparison fails closed instead of depending on manual copy/paste

---

## What already exists (do not re-solve)

### Core chain kernel
- `trnm-state`
- `trnm-pouw`
- `trnm-executor`
- `trnm-node`
- `trnm-mempool`
- `trnm-rpc`
- `trnm-worker-agent`
- `trnm-cli`

### Existing proof-of-life / release-prep assets
- workspace tests and many crate gates
- rollback / replay / recovery validation paths
- state-root audit scripts
- RC evidence / local release evidence scripts
- testnet preflight script
- multi-node local configs
- BFT smoke / query audit / worker receipt gates

### Important implication
The biggest remaining problem is **not** "missing blockchain core logic".
The biggest remaining problem is:

> **the production perimeter around the core is not yet complete enough for public mainnet.**

---

# P0 — True mainnet launch blockers

These are the items that should block any public-mainnet claim.

## P0.1 Real network layer / peer formation / sync

### Current state
Node config currently exposes only a minimal address surface:
- `node_id`
- `rpc_addr`
- `p2p_addr`

The runtime bootstrap path still initializes demo state/mempool for local execution.

### Missing
- peer discovery
- bootstrap peer management
- stable gossip / transport behavior
- state sync / snapshot sync / fast catch-up
- peer scoring / abuse handling / network-level backpressure
- explicit join/rejoin behavior for lagging nodes

### Why P0
Without this, TRNM can run local devnets and test loops, but it is not yet a credible public network runtime.

---

## P0.2 Genesis + validator/operator lifecycle

### Current state
The repository has local node configs and preflight scripts, but not a clearly closed public-validator lifecycle.

### Missing
- genesis generation + validation flow
- validator key ceremony / validator identity process
- validator replacement / rotation workflow
- chain upgrade / rollback operator drill
- disaster recovery and node rebuild SOP

### Partial coverage now present
- genesis generation / validation checklist: `docs/runbooks/genesis-generation-checklist.md`
- validator bootstrap / re-bootstrap operational guide: `docs/runbooks/validator-bootstrap-rebootstrap.md`
- validator replacement / rotation / DR handoff guide: `docs/runbooks/validator-rotation-dr.md`
- fail-closed DR handoff field extraction helper: `scripts/v2/extract_validator_rotation_dr_fields.sh`
- signed operator ceremony packet skeleton for replacement / rotation / DR handoff is now documented in `docs/runbooks/validator-rotation-dr.md`

### Still open inside this area
- bootstrap / replacement / rotation / DR procedures are documented, but still need a real signed rehearsal packet produced from live operator artifacts instead of documentation-only closure
- no validator replacement / rotation automation
- no disaster-recovery rebuild drill with captured evidence

### Why P0
A public mainnet is not only a binary; it is an operator system.
If operator lifecycle is unclear, the chain is not actually launchable.

---

## P0.3 Secure wallet / signer / key management path

### Current state
`trnm-cli` explicitly describes itself as:
- wallet/query/tx **MVP**
- wallet create is an MVP placeholder path

### Missing
- secure keystore model
- offline signing flow
- multi-sig / HSM / remote signer integration path
- wallet recovery/import/export policy
- clear nonce / fee / signing UX and safety checks
- key rotation and compromise response runbook

### Why P0
Public mainnet without a secure signer story is not acceptable for operators or users.

---

## P0.4 Indexer / explorer / stable read-model

### Current state
The repo contains a minimal local explorer script, explicitly local-only and log/json backed.

### Missing
- durable indexer
- tx/block/account/event read-model
- historical query path
- stable explorer backend/API
- archive/read replica strategy
- production query performance expectations

### Why P0
A public chain without a stable read surface becomes operationally opaque and unusable for integrators.

---

## P0.5 Unified observability / alerting / SRE view

### Current state
There are partial metrics, smoke checks, benchmark outputs, and localized Prometheus-style surfaces.
There is not yet one clearly unified production observability plane.
A minimum operator-visible contract is now frozen in `docs/runbooks/mainnet-observability-minimum-contract.md` for the currently shipped health aliases, `trnm-rpc` health body, `trnm-node` incident-summary fields, and `trnm-worker-agent` handoff/batch-summary shapes.

### Partial coverage now present
- `docs/runbooks/mainnet-observability-alerting-starter-pack.md` defines one starter alert set, one shared severity vocabulary, one minimum dashboard bundle, and one incident handoff block that preserves replay / rollback pointers.
- `docs/runbooks/oracle-observability-alerts.md` provides the oracle-specific drill-down contract while preserving the shared observability label block.

### Missing
- node/rpc/worker/oracle/bridge unified metrics contract beyond that minimum frozen operator contract
- production exporter path
- dashboards wired to the shared stable panel names / first-stop routing contract
- alert thresholds frozen beyond the starter pack heuristics
- incident labels / severity conventions consistently emitted in pages, dashboard annotations, and tickets
- replay + failure-attribution workflow tied to observability across real rehearsal evidence, not only runbook text

### Why P0
Mainnet incidents are inevitable.
Without observability and alerting, recovery becomes guesswork.

---

## P0.6 Economics / anti-spam / fee boundary freeze

### Current state
TRNM already has substantial work around free-ingress, QoS, lane fairness, challenge bonds, and slash logic.

### Missing
- final public mempool admission policy
- minimum fee / anti-spam thresholds
- sponsor/free-ingress boundary definition
- storage/evidence retention pricing policy
- resource abuse protection under sustained load
- frozen economic parameter set for launch

### Why P0
Mainnet begins exactly where adversarial usage begins.
If anti-spam and pricing remain fluid, launch risk is too high.

### Day-1 freeze tuple (minimum launch helper)
To turn this blocker into a ship/no-ship gate, freeze one explicit tuple before any public mainnet cut:
- **ingress class split**: which flows stay free-ingress, which require fee-like admission, and which remain sponsor-only
- **sponsor boundary**: exact caller/classes allowed to subsidize admission, plus per-epoch caps and revocation path
- **retention pricing rule**: how long proofs/evidence/collateral snapshots remain queryable and which actor pays for storage-heavy paths
- **anti-spam floor**: minimum admission threshold (fee floor, bond floor, or rate-limit budget) for sustained public load
- **override authority**: who may change the tuple pre-launch and what timelock/audit evidence is required

If any one of these five elements is still "to be decided", economics should remain **NO-GO** for public-mainnet release.

For a concrete review sheet, see `trillionnium/docs/release/TRNM_MAINNET_ECONOMICS_FREEZE_HELPER_2026-03-27.md`.

---

# P1 — Highly important, but can trail P0 if launch scope is narrow

## P1.1 Oracle online subsystem

### Current state
`trnm-oracle` looks like a real validation/reporting library plus offline baseline tooling.
But it is still much closer to an offline validator than a live chain-integrated oracle subsystem.

### Missing
- node ingest path for oracle observations
- state persistence for oracle snapshot/policy lifecycle
- stable RPC query surface for oracle state
- replay/recovery semantics for oracle data
- high-volume feed path and operational metrics

### Launch effect
If TRNM public launch does **not** depend on oracle-secured features on day 1, this may trail P0.
If oracle-backed settlement is part of day-1 positioning, it becomes P0.

---

## P1.2 Bridge productionization

### Current state
The crate is still explicitly named `trnm-bridge-poc`.
That is the right level of honesty.

### Missing
- finality/checkpoint contract for bridge consumers
- proof material surface
- relayer trust model hardening
- failure recovery + settlement audit trail
- bridge operator runbook
- explicit settlement confirmation boundary documentation so operators can state the fail-closed rule in plain terms (`target < confirm <= source + 1`, with the stricter `source + 1` requirement once target has already caught up to source); see `trillionnium/docs/release/TRNM_BRIDGE_SETTLEMENT_AUDIT_NOTE_2026-04-02.md`
- frozen settlement audit field contract (`phase`, `heartbeat_source_height`, `heartbeat_target_height`, `heartbeat_latency_ms`, `confirm_height`, `confirm_reason`) so replay and incident review quote one canonical evidence surface instead of ad-hoc log phrasing; current operator note: `trillionnium/docs/release/TRNM_BRIDGE_SETTLEMENT_AUDIT_NOTE_2026-04-02.md`

### Launch effect
If bridge is not part of day-1 launch promise, this can trail.
If cross-chain positioning is public day-1, it becomes P0.

---

## P1.3 Verifier / proof sidecar productization

### Current state
TEE / ZK / verification paths have meaningful code and contracts in motion, but the repository does not currently justify saying a production verifier subsystem is fully in-place.

### Missing
- stable deployable verifier service boundary
- operational packaging
- trust/retry/failure semantics under production conditions
- audit/replay evidence path for verifier outages or mismatches

### Closure note
- verifier / DA / checkpoint sidecar closure checklist: `trillionnium/docs/release/TRNM_VERIFIER_DA_CHECKPOINT_SIDECAR_CLOSURE_2026-03-31.md`

### Launch effect
Can trail if day-1 mainnet only requires the core task lifecycle and local trust assumptions.
Cannot trail if "trusted verification as a product" is part of the public launch claim.

---

## P1.4 Governance / upgrade discipline hardening

### Current state
TRNM already has meaningful governance-sensitive logic and timelock/security coverage.

### Missing
- fully typed governance registry closure
- upgrade playbooks with operator sign-off checkpoints
- schema migration discipline for public upgrade cycles
- clearly frozen set of launch-sensitive parameters

### Launch effect
Launchable chains still need this very early, but it can proceed in parallel with late P0 closure.

---

# P2 — Valuable launch-adjacent work, but not first blocking ring

## P2.1 Better public frontend / wallet UX
- richer user wallet UX
- integrated task dashboard
- better explorer polish
- self-serve user onboarding

## P2.2 Broader ecosystem integrations
- SDK polish
- partner-facing client examples
- external indexer adapters
- richer analytics endpoints

## P2.3 Full bridge/oracle/verifier product narrative
- not just the code path,
- but the external platform story, packaging, and support posture

---

# Minimal mainnet module checklist

If TRNM wants the **smallest credible public mainnet scope**, the minimum set should be:

## Core already present
- node
- state
- executor
- mempool
- rpc
- PoUW state machine
- worker-agent path

## Must close before launch
1. network formation + sync
2. genesis + validator/operator lifecycle
3. secure wallet/signer path
4. indexer/explorer/read-model
5. unified observability + alerting
6. launch economics + anti-spam freeze

## Can trail only if explicitly out-of-scope for day 1
7. oracle online subsystem
8. bridge productionization
9. verifier sidecar productization

---

# Recommended next 4-week closing sequence

## Week 1 — Freeze launch scope and operational truth

### Goals
- define the exact day-1 launch promise
- decide what is out-of-scope
- stop mixing internal devnet readiness with public mainnet language

### Required outputs
1. one public-scope definition:
   - core-only mainnet
   - or core + oracle
   - or core + oracle + bridge
2. one launch-blocker board with owners
3. one operator truth-source doc
4. one frozen list of P0 module owners

### Rule
Anything not required for the chosen day-1 promise must not be allowed to silently expand P0.

---

## Week 2 — Close ops/network foundations

### Focus
- genesis process
- validator bootstrap/recovery
- peer formation and join/rejoin behavior
- node sync expectations

### Required outputs
- genesis generation checklist
- validator bootstrap runbook
- network formation smoke test
- node recovery / catch-up acceptance criteria

---

## Week 3 — Close user/operator surfaces

### Focus
- signer / wallet hardening
- explorer/indexer minimum viable public read path
- alerting and unified observability

### Required outputs
- secure wallet/signer policy
- minimum explorer/indexer service
- alert set (node down / lag / replay failure / rpc unhealthy / worker failure)
- one dashboard bundle or equivalent metrics contract

---

## Week 4 — Freeze economics and run full prelaunch rehearsal

### Focus
- anti-spam / admission / sponsor boundaries
- launch parameter freeze
- full prelaunch rehearsal

### Required outputs
- launch parameter sheet
- adversarial spam/fairness rehearsal
- incident rollback drill
- go/no-go document for public launch
- one path-resolved rehearsal evidence bundle that names the exact `summary.txt` / `manifest.txt` used for the decision, together with matching `git_branch=`, `git_head=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_status_summary=`, `truth_source=`, `historical_evidence_only=`, `evidence_scope=`, `rollback_command=`, and `replay_command=` fields, plus both artifact timestamps preserved as `summary_generated_at=` and `manifest_generated_at=` rather than collapsed into one assumed-to-match `generated_at=` value; prefer `./scripts/v2/extract_release_handoff_fields.sh` so the handoff fails closed on missing artifacts or cross-artifact identity drift instead of relying on manually recopied field snippets

Interpretation rule:
- a Week-4 rehearsal is not "mainnet-ready evidence" unless the operator can point to concrete artifact paths and those identity fields agree across the local evidence summary and RC manifest;
- quoting PASS lines without the artifact paths and identity fields is only anecdote, not launch evidence.

---

# Suggested owner map by module family

## Core launch ring
- `trnm-node` / networking / recovery: owner A
- `trnm-rpc` / read surface / health: owner B
- `trnm-cli` / wallet/signer path: owner C
- ops/genesis/validator lifecycle: owner D
- observability / alerting / dashboards: owner E
- economics / mempool admission / sponsor boundary: owner F

## Secondary ring
- `trnm-oracle`: owner G
- `trnm-bridge-poc`: owner H
- verifier sidecar / proof service path: owner I

---

# Go / No-Go interpretation

## No-Go for public mainnet if any P0 item remains ambiguous
Especially if:
- the network can only be reproduced as a local static devnet,
- the signer path is still MVP-only,
- the explorer/read path is still local-script grade,
- the observability path is fragmented,
- or launch economics are still intentionally fluid.

## Possible Go for restricted internal/test operator launch if:
- the scope is explicitly devnet / RC / internal testnet,
- P0 items are being closed under operator control,
- and no public mainnet claim is made.

---

# Final judgment

TRNM is no longer at the "empty architecture" stage.
It has enough kernel substance that the correct next move is **not** broad new feature expansion.

The correct next move is:

> **close the production perimeter around the core and freeze the day-1 launch scope.**

That is the shortest path from "impressive internal system" to "credible public network candidate."
