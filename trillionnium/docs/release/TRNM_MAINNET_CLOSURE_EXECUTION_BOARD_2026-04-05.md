# TRNM Mainnet Closure Execution Board (2026-04-05)

> BL09 retirement-prep note: any retained `trnm-pouw` crate, path, command, or test-slice references in this closure board should be read as migration-era compatibility, release-closure guardrails, or provenance / audit evidence only. Once PoCO becomes the primary settlement path, these retained surfaces are not the default payout authority and do not re-authorize default work-unit payout paths.

## Truth-source snapshot

This board is tied to the **current local integrated `main`** and should be read together with:
- `RELEASE_READINESS.md`
- `trillionnium/docs/release/TRNM_MAINNET_READINESS_REASSESSMENT_2026-04-05.md`
- `trillionnium/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `trillionnium/docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`
- `trillionnium/docs/release/TRNM_MAINNET_LAUNCH_COUNTDOWN_2026-04-03.md`

Snapshot evaluated:
- local `main = 161b42e34`
- `origin/main = 35da4109e92321ecfdd9aa86b0738b968ea519d9`
- local `main` vs `origin/main`: **ahead 614**
- local branch/worktree shape: **single-branch / single-worktree**

Boundary:
- this document is an **execution board**, not a release-ready claim;
- it translates the current readiness assessment into concrete closure packages;
- it does not imply `origin/main` has already inherited the same local snapshot.

---

## Headline judgment

Current stage:

> **late RC-prep / prelaunch-closure**

Current launch distance:
- **6 P0 closure packages**
- **1 integrated launch-gate package**
- plus **3 optional P1 packages** if Day-1 scope includes oracle / bridge / verifier productization

Practical reading rule:
- the repository is no longer mainly blocked by branch fragmentation;
- it is blocked by **operator-grade production-perimeter closure**.

---

## Priority order

### Rank 1 — P0: Public read surface / indexer / explorer / historical read-model
### Rank 2 — P0: Secure signer / keystore / offline signing
### Rank 3 — P0: Real network formation / sync / join-rejoin
### Rank 4 — Launch gate: Integrated prelaunch rehearsal / evidence / GO-NO-GO
### Rank 5 — P0: Unified observability / alerting / SRE plane
### Rank 6 — P0: Economics / anti-spam / fee boundary freeze
### Rank 7 — P0: Validator / operator lifecycle closure

Optional P1 packages if Day-1 scope explicitly requires them:
- P1.1 oracle online subsystem
- P1.2 bridge settlement / relay productization
- P1.3 verifier / checkpoint sidecar productization

---

# Execution board

## Package A — Rank 1 / P0
## Public read surface / indexer / explorer / historical read-model

### Current status
**OPEN — highest priority, not placeholder, not closeable on current evidence**

Rank1 refresh anchor on current local-main evidence:
- `R7` keeps the Day-1 read contract passing on current `main` while repo-local adapter co-sign remains explicitly external
- latest `R8` gate refresh now proves a future `height_ingest_manifest` row can commit by itself while `materialization_state` and `ingest_checkpoint` stay at the prior height, so the open atomicity gap now spans manifest, materialization, and checkpoint state instead of a placeholder-only scaffold concern
- latest `R9` evidence set keeps the read surface substantive by passing unknown-local-height degrade, wrapped parent-hash rejection, corrupt-latest snapshot fallback, and degraded-before-stalled lag classification on top of the earlier resume and hash fail-closed coverage
- `R11` freezes the historical replay / retention tuple and preserves the placeholder-versus-durable service-summary boundary for the intended durable target
- latest `R10` evidence now records `WAITING_FOR_EVIDENCE_PACKET`: doc-only packet work is exhausted and no filled non-template `TRNM_DURABLE_READ_SERVICE_HANDOFF` packet with real non-placeholder deployment/runtime/replay/rollback evidence exists on the evaluated snapshot

### Why this package exists
The chain kernel is much stronger than before, but TRNM still does not have a clearly closed durable public read surface.

### What already exists
- Day-1 read-contract discussion and contract tables
- explorer scaffold runbook
- explorer scaffold handoff template
- durable-read service handoff template
- more query/read-only structure on current main

### What is still missing
- durable indexer pipeline
- historical read-model
- stable explorer backend/API
- archive / read-replica policy
- public read retention / SLO policy
- non-placeholder deployment + replay/recovery + lag evidence packet

### Exit criteria
- one explicit Day-1 minimum public read surface
- one durable indexer pipeline design or implementation boundary
- one historical replay / retention policy
- one operator-grade explorer/indexer deployment packet
- one proof that the read surface is no longer only placeholder scaffold

### Evidence expected in the closure packet
- indexer pipeline boundary note
- replay source / retention policy note
- deployment runbook or service packet
- query/read-model evidence bundle
- explicit statement of what is Day-1 supported vs deferred

### First execution slice
1. Freeze Day-1 minimum public read surface.
2. Choose durable indexer persistence + replay source.
3. Convert scaffold/handoff templates into one non-placeholder operator packet.

---

## Package B — Rank 2 / P0
## Secure signer / keystore / offline signing

### Current status
**OPEN — second highest priority, materially advanced but not closeable on current evidence**

Signer refresh anchor on current local-main evidence:
- `R14` now preserves one real offline-signing transcript path on the live `submit-consumption-receipt` -> `tx query` -> `tx wait` flow, but keeps closure conditional because ticket-path identity bind and clean-owner-context are still red
- `R15` freezes the Day-1 keystore answer to one explicitly owned local cold signer using an ephemeral local wallet store and offline-first submit-later evidence
- `R16` proves the signer rotation / compromise SOP fails closed on assignment-path versus git-root mismatch and on dirty shared owner context, so the rehearsal packet exists but the gate is still not ready to close
- `R17` freezes remote signer / HSM / multisig as out-of-scope Day-1 launch dependencies unless separate operator evidence exists
- `R15` and `R17` now each carry the Day-1 signer safety checklist excerpt, but no current operator-facing signing packet yet assembles the checklist, threat model, and chosen signer flow into one release handoff

### Why this package exists
`trnm-cli` is clearly better hardened, but the signer path is still explicitly MVP-level and not yet a finished public-mainnet operator story.

### What already exists
- CLI wallet/query/tx MVP path
- stronger keystore path hygiene
- stronger signer input fail-closed behavior
- signer-related hardening on current main
- approved Day-1 keystore model frozen in `R15`
- remote signer / HSM / multisig Day-1 posture frozen in `R17`
- signer safety checklist excerpt now attached in the current signer architecture and threat-model packets

### What is still missing
- operator-grade offline signing flow
- compromise / rotation response bound to launch
- one operator-facing signing packet that ties the frozen keystore model, threat model, checklist excerpt, and chosen signer flow into one release handoff

### Exit criteria
- one approved keystore architecture
- one real offline-signing path
- one compromise / rotation SOP
- one signer safety checklist
- one operator packet tying threat model to the chosen signer flow

### Evidence expected in the closure packet
- signer threat model
- keystore architecture note
- offline signing path transcript
- rotation / compromise SOP
- launch packet checklist excerpt

### First execution slice
1. Freeze Day-1 signer threat model.
2. Pick keystore / offline-signing architecture.
3. Produce one operator-facing signing packet from the chosen model.

---

## Package C — Rank 3 / P0
## Real network formation / sync / join-rejoin

### Current status
**OPEN — third highest priority**

### Why this package exists
Current `trnm-node` is much stronger at fail-closed bootstrap/config/recovery, but public-network semantics are still thinner than required for launch.

### What already exists
- bootstrap topology hardening
- stronger path / canonical-path diagnostics
- stronger startup-preflight matrix coverage
- stronger recovery / WAL / checkpoint behavior
- more operator-visible fail-closed config behavior

### What is still missing
- explicit bootstrap peer management for public-network operation
- sync / catch-up / rejoin acceptance matrix
- lagging-node policy
- operator-facing sync diagnostics
- realistic multi-node formation / catch-up rehearsal evidence

### Exit criteria
- one bootstrap / join / rejoin model
- one acceptance matrix for sync/catch-up
- one operator diagnosis flow
- one multi-node rehearsal with evidence

### Evidence expected in the closure packet
- bootstrap topology note
- join/rejoin acceptance table
- sync diagnostic contract
- rehearsal transcript / evidence

### First execution slice
1. Freeze bootstrap/join/rejoin model.
2. Write the catch-up acceptance matrix.
3. Run one multi-node sync/join-rejoin rehearsal on current mainline.

---

## Package D — Rank 4 / Launch gate
## Integrated prelaunch rehearsal / evidence / GO-NO-GO

### Current status
**OPEN — required before any public-mainnet claim**

### Why this package exists
Even if Packages A–C advance, TRNM still needs one integrated, current-mainline, operator-grade launch packet.

### What already exists
- RC/rehearsal/handoff discipline
- release/readiness truth-source discipline
- local evidence scripts
- rollback/replay documentation

### What is still missing
- one full rehearsal on the current integrated mainline
- one path-resolved evidence bundle
- one current-head GO / CONDITIONAL GO / NO-GO memo
- one rollback drill attached to the same packet

### Exit criteria
- full rehearsal green on the evaluated mainline
- summary/manifest identity preserved and cross-checked
- rollback preserved in the same packet
- operator decision packet complete

### Evidence expected in the closure packet
- `summary.txt`
- `manifest.txt`
- path-resolved handoff transcript
- replay / rollback command block
- final decision memo

### First execution slice
1. Freeze rehearsal scope against the current integrated mainline.
2. Produce one path-resolved evidence bundle.
3. Generate one explicit GO / CONDITIONAL GO / NO-GO memo from that bundle.

---

## Package E — Rank 5 / P0
## Unified observability / alerting / SRE plane

### Current status
**OPEN — starter-pack exists, operational plane still incomplete**

### Why this package exists
The starter pack closes runbook-shape, not the full launch blocker.

### What already exists
- starter alert family set
- shared label/severity vocabulary
- minimum dashboard bundle guidance
- incident handoff block with replay/rollback pointers

### What is still missing
- real exporter payload contract enforcement
- dashboard wiring using stable panel names
- frozen thresholds beyond heuristics
- emitted label/severity consistency in real paging/ticket flow
- replay/failure-attribution proven by rehearsal evidence

### Exit criteria
- one metrics/exporter contract
- one real dashboard pack
- one alert rules pack
- one evidence-backed incident workflow

### Evidence expected in the closure packet
- emitted payload examples
- dashboard links / screenshots / panel map
- alert rules bundle
- incident transcript with stable labels

### First execution slice
1. Freeze exporter dimensions / dashboard panel names.
2. Turn starter-pack assumptions into emitted payload contracts.
3. Bind one rehearsal incident packet to replay/rollback evidence.

---

## Package F — Rank 6 / P0
## Economics / anti-spam / fee boundary freeze

### Current status
**OPEN — code exists, launch freeze still missing**

### Why this package exists
Current code already carries substantial anti-spam / sponsor / fairness logic, but public-mainnet launch still needs a frozen Day-1 economics tuple.

### What already exists
- anti-spam / QoS / sponsor / fairness code on main
- economics freeze helper doc
- evidence-anchor tests and compile slices

### What is still missing
- ingress class split
- sponsor boundary and caps, including revocation queue disposition
- sponsor duplicate-retention stance during revocation/drain-only
- retention pricing rule
- anti-spam/admission floor
- change authority / timelock for prelaunch updates
- explicit launch freeze packet

### Exit criteria
- one frozen Day-1 economics tuple
- one spam/fairness rehearsal against that tuple
- one launch packet citing the freeze tuple and evidence anchors

### Evidence expected in the closure packet
- tuple freeze memo naming the Day-1 ingress split, sponsor boundary/caps, sponsor revocation queue disposition, sponsor duplicate-retention stance, retention pricing rule, anti-spam floor, and prelaunch override authority/timelock
- anti-spam/admission evidence, anchored by at least:
  - `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drain_only_duplicate_retention_bound -q`
  - `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q`
  - `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_reserve_clamp_borrow_policy_bound -q`
- retention/freeze evidence, anchored by at least:
  - `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw --lib tests::legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -- --exact -q`
  - `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q`
- tuple integrity compile slice:
  - `cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q`
- compile-slice integrity check

### First execution slice
1. Freeze ingress/sponsor/retention tuple.
2. Run one spam/fairness rehearsal.
3. Bind that result into the launch packet.

---

## Package G — Rank 7 / P0
## Validator / operator lifecycle closure

### Current status
**OPEN — documented but not operator-closed**

### Why this package exists
Genesis / bootstrap / rotation / DR runbooks exist, but operational closure still depends on real operator-grade evidence rather than documentation skeletons.

### What already exists
- genesis checklist and candidate bundle
- bootstrap / re-bootstrap runbook
- rotation / DR runbook
- config-bundle checker and ceremony packet skeleton

### What is still missing
- real signed ceremony packet
- real operator ownership / acknowledgment evidence
- real bootstrap handoff packet
- DR rebuild / replacement / rotation evidence

### Exit criteria
- one real genesis/operator packet
- one bootstrap handoff evidence bundle
- one DR/rebuild or rotation evidence bundle
- one current-mainline operator lifecycle packet suitable for launch review

### Evidence expected in the closure packet
- signed ceremony packet or equivalent operator acknowledgment packet
- handoff transcript
- DR/replay/rollback evidence
- validator ownership / identity bundle

### First execution slice
1. Convert local candidate artifact into a real operator packet.
2. Attach ownership/acknowledgment evidence.
3. Run one bootstrap/handoff + one DR/rotation evidence cycle.

---

# Optional P1 packages

## P1.1 Oracle online subsystem
Keep outside the immediate gate unless Day-1 scope explicitly includes oracle productization.

## P1.2 Bridge settlement / relay productization
Keep outside the immediate gate unless Day-1 scope explicitly includes bridge launch semantics.

## P1.3 Verifier / checkpoint sidecar productization
Keep outside the immediate gate unless Day-1 scope explicitly includes verifier/sidecar productionization.

---

## Operating rule for the next phase

Do **not** measure progress primarily by:
- number of commits
- historical lane counts
- number of merged residual patches

Measure progress by whether one of the seven packages above has produced:
1. a tighter scope boundary,
2. a real operator-grade evidence packet,
3. and a credible exit-criteria downgrade from OPEN toward CLOSEABLE.

---

## Final board judgment

For the current local integrated `main`:
- branch cleanup is no longer the issue;
- residual absorption is no longer the issue;
- the remaining launch distance is now almost entirely the **seven closure packages above**.

The shortest honest path to public-mainnet candidacy remains:
1. Rank 1
2. Rank 2
3. Rank 3
4. Rank 4
5. then Rank 5–7 as the release packet is hardened.
