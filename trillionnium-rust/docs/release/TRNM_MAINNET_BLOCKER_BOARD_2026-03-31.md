# TRNM Mainnet Blocker Board (2026-03-31)

## Truth-source snapshot

- Repository snapshot evaluated: `origin/main = 9ea9e7751de1d571c6b1842e01fc66314e844356`
- Snapshot note: refreshed after the 2026-03-31 mainline cleanup that removed placeholder library-crate bin targets, so rehearsal / go-no-go discussions quote the current integrated mainline rather than the older `8ff9f1fe45bdf3f027bce7d86ae51394c3df5d86` snapshot.
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
- artifact identities consistent across preflight / summary / manifest, with lane binding proven from the ticket-assigned worktree/branch rather than inferred from the shell
- the packet preserves `generated_at=` and `git_status_summary=clean` next to `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, and `git_worktree_branch_ref_match=true`, so reviewers can prove both timing and clean-tree identity from artifacts instead of scrollback memory
- `truth_source=`, `historical_evidence_only=`, and `evidence_scope=` remain adjacent to the quoted PASS/GO language, and `rollback_command=` / `replay_command=` are preserved verbatim from generated artifacts
- the packet also preserves the path-resolved preflight decision artifact (or saved helper transcript) closely enough to quote `result=`, `generated_at=`, `git_status_summary=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `rollback_command=`, and `replay_command=` for the fast-fail stage instead of treating preflight as undocumented terminal context
- the `extract_release_handoff_fields.sh` output is itself preserved as a path-resolved helper transcript (for example via `tee`), so reviewers can quote `summary_generated_at=`, `manifest_generated_at=`, and the preserved rollback/replay lines from a saved artifact instead of terminal memory
- signed operator decision packet

**Next actions**
1. define rehearsal scope against current `origin/main`
2. bind the run to the ticket-assigned worktree/branch with `./scripts/v2/verify_lane_worktree.sh --expected-worktree-root ... --expected-branch-ref ...` before any release/evidence script runs
3. run full rehearsal with a path-resolved evidence bundle, then extract/compare the packet via `./scripts/v2/extract_release_handoff_fields.sh`, saving the helper output to a path-resolved transcript so `generated_at=`, `git_status_summary=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_expected_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `rollback_command=`, and `replay_command=` are quoted from artifacts instead of terminal memory
4. produce formal GO/NOGO memo

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

**Next actions**
1. freeze ingress/sponsor/retention tuple
2. run one spam/fairness rehearsal against frozen tuple
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

### P1.3 Verifier / proof sidecar productization
Keep as P1 unless “trusted verification as a product” is part of the public launch claim.

## Recommended execution order from here

### Phase A — Freeze launch scope and ownership
1. freeze Day-1 promise
2. confirm whether oracle / bridge / verifier are in or out
3. assign one owner per remaining P0 package

### Phase B — Close the three hardest product surfaces
1. explorer/indexer/read-model
2. signer/keystore/offline signing
3. network formation/sync/join-rejoin

### Phase C — Close operator and SRE perimeter
1. observability/alerting
2. economics freeze
3. validator/operator lifecycle

### Phase D — Run integrated launch rehearsal
1. full prelaunch rehearsal on current `origin/main`
2. evidence bundle + rollback references
3. GO / CONDITIONAL GO / NO-GO decision

## Go / No-Go rule

No public-mainnet claim should be made if **any** of the following remain ambiguous:
- public read surface
- signer/key-management path
- network formation/sync behavior
- unified observability/alerting
- launch economics freeze
- operator lifecycle
- integrated rehearsal evidence / rollback path

## Final judgment

TRNM has crossed out of “fragmented lane progress” and into “integrated release-closure mainline.”
That is meaningful progress.

But the remaining problem is now sharper:

> the launch blocker set is no longer branch management or unfinished lane absorption;
> it is the still-open production perimeter required for a credible public mainnet claim.
