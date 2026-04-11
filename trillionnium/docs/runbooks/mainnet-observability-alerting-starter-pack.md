# Mainnet Observability / Alerting Starter Pack

This runbook defines the **smallest operator-facing observability bundle** that TRNM should keep stable for public-mainnet rehearsal.

It does **not** claim the observability plane is complete.
It closes one practical gap called out by the mainnet blocker docs:

- one starter alert set
- one shared severity vocabulary
- one minimum dashboard bundle
- one incident handoff block that preserves replay / rollback pointers

Companion truth sources:

- `RELEASE_READINESS.md`
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`
- `trillionnium/docs/runbooks/local-release-evidence.md`
- `trillionnium/docs/runbooks/bft-checkpoint-wal-recovery.md`
- `trillionnium/docs/runbooks/oracle-observability-alerts.md`

## What this starter pack closes vs. what remains open

This document is meant to close the **runbook-shape** part of P0.5, not the whole public-mainnet observability blocker.

What this runbook closes now:
- one shared label block across pages, dashboard annotations, and incident tickets;
- one starter alert family set with default severity / replay / rollback expectations;
- one minimum dashboard bundle with stable panel names and first-stop routing;
- one compact incident evidence block that preserves `replay_command=` / `rollback_command=` pointers.

What remains open even after this runbook exists:
- node/rpc/worker/oracle/bridge metrics contract enforcement in real exporters and emitted page payloads;
- production dashboard wiring that actually uses the stable panel names and first-stop routing contract from this document;
- alert thresholds frozen beyond starter-pack heuristics and verified against rehearsal traffic;
- incident labels / severity conventions emitted consistently by the real paging/ticketing path, not only copied from runbook examples;
- replay / failure-attribution linkage proven against generated rehearsal evidence, not only described in prose.

Interpretation rule:
- if operators can only point to this markdown file, the P0.5 blocker is still open;
- only real exporter payloads, dashboard annotations, alert rules, and rehearsal evidence may downgrade the blocker from documentation-only coverage to operational coverage.

---

## Scope

Use this starter pack for the minimum Day-1 production perimeter across these planes:

- `service=node`
- `service=rpc`
- `service=worker`
- `service=oracle`
- `service=bridge`

If a service-specific runbook already exists, keep using it for deeper triage.
This document standardizes the **shared paging / dashboard / incident handoff contract**.

---

## Frozen metrics / alert dimension contract

Before mainnet rehearsal, operators should treat the following dimensions as append-stable for the starter pack.
Dashboards and alert rules may add panels or thresholds later, but they should not silently rename these keys across services.

### Required shared dimensions

| Dimension | Required values / shape | Why it is frozen for the starter pack |
| --- | --- | --- |
| `plane` | `observability` | Keeps observability incidents searchable as one operator plane. |
| `service` | `node`, `rpc`, `worker`, `oracle`, `bridge`, `any` | Preserves one cross-service routing surface, including starter-pack incidents like `contract-drift` that are not owned by a single service. |
| `severity` | `sev0`, `sev1`, `sev2`, `sev3` | Prevents page/ticket/dashboard severity drift. |
| `signal` | `node-down`, `sync-lag`, `replay-failure`, `rpc-unhealthy`, `worker-failure`, `oracle-anomaly`, `bridge-anomaly`, `contract-drift` | Keeps alert families stable enough for paging and dashboard links. |
| `needs_replay` | `yes`, `no` | Forces responders to distinguish evidence-required incidents from pure telemetry noise. |
| `needs_rollback` | `yes`, `no` | Preserves rollback intent as an explicit operator decision, not tribal knowledge. |
| `first_stop` | one stable panel name from this runbook, or `unknown` | Freezes dashboard/ticket/page routing so responders open the same first surface during incidents. |

### Stability rules

- do not rename the shared dimensions above during a rehearsal window;
- if a service needs extra dimensions, add them without replacing the shared keys;
- if an alert payload, dashboard annotation, or incident ticket cannot populate the shared keys, classify that handoff as incomplete;
- if dashboard math depends on a metric rename or label remap that is not reflected in the incident payload, treat the resulting mismatch as `signal=contract-drift`.

This is a starter-pack contract, not a claim that all long-term observability schemas are finalized.
It exists to keep the first dashboard pack, first alert pack, and first incident workflow speaking the same language.

---

## Required incident labels

Every alert page, dashboard share link, and incident ticket should carry the same small label block:

- `plane=observability`
- `service=<node|rpc|worker|oracle|bridge|any>`
- `severity=<sev0|sev1|sev2|sev3>`
- `signal=<node-down|sync-lag|replay-failure|rpc-unhealthy|worker-failure|oracle-anomaly|bridge-anomaly|contract-drift>`
- `verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|ingest-latency|contract-drift|n/a>`
- `needs_replay=<yes|no>`
- `needs_rollback=<yes|no>`
- `first_stop=<stable-panel-name-from-this-runbook|unknown>`

Rules:

- `needs_replay=yes` for every `sev0` / `sev1` incident.
- `needs_rollback=yes` only when a concrete emitted `rollback_command=` exists or rollback is the active mitigation choice.
- `first_stop=` must exactly match one stable panel name from this runbook; use `unknown` rather than inventing a new alias.
- set `verdict=n/a` for non-oracle incidents; for `service=oracle`, preserve `verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|ingest-latency|contract-drift>` from `trillionnium/docs/runbooks/oracle-observability-alerts.md`.
- if a screenshot or dashboard link is shared without this label block, treat the handoff as incomplete.

---

## Shared severity mapping

Use one severity vocabulary across dashboards, pages, and handoff notes.

### `sev0`

Observability or evidence is untrustworthy enough that operators should stop relying on automated interpretation.

Examples:

- dashboard signal contradicts replay/evidence artifacts
- emitted evidence bundle is missing or identity-drifted during an active incident
- metrics/schema contract drift makes page math unreliable

Expected action:

- page immediately
- freeze automated interpretation
- open incident with evidence pointers

### `sev1`

Live mainnet-impacting or near-mainnet-impacting degradation.

Examples:

- node unavailable
- sustained sync lag / join-rejoin failure
- rpc unhealthy for consecutive windows
- worker failures blocking throughput
- oracle accepts stall / quorum collapse

Expected action:

- page on-call immediately
- attach replay / rollback pointers
- assign one responder to evidence reconciliation

### `sev2`

Degraded but still attributable and bounded.

Examples:

- replay failure limited to one drill path
- stale-wave / drift anomaly with bounded blast radius
- elevated round-change / rollback pattern without service unavailability

Expected action:

- investigate in the active on-call window
- promote if persistence increases or user-facing impact spreads

### `sev3`

Early-warning or informational only.

Examples:

- one-off unhealthy probe blip
- latency trend drift without acceptance or availability impact
- single-window worker retry spike that self-recovers

Expected action:

- record in dashboard notes / shift handoff
- no page by default

## Severity promotion / override rules

Use these override rules before closing or reclassifying an incident.
They keep the starter alert set from drifting when the same symptom appears across multiple panels.

| Current class | Promote when | Target class | Why |
| --- | --- | --- | --- |
| `sev3` | the same signal fires in 2 consecutive windows or appears on more than 1 validator / endpoint / worker queue | `sev2` | persistence or spread means the issue is no longer informational noise |
| `sev2` | user-facing read paths, validator participation, or worker receipt flow are degraded for 2 consecutive windows | `sev1` | bounded incidents become launch blockers once they threaten live service continuity |
| `sev2` | replay / rollback evidence is missing during active mitigation | `sev1` | responders should page before they improvise recovery from memory |
| `sev1` | dashboard math, label mapping, or emitted evidence identity is contradicted or missing | `sev0` | the observability plane itself is no longer trustworthy |
| any | 2 signals with different severities fire together and one is `contract-drift` or `replay-failure` | higher of the two, with `contract-drift` winning ties | evidence-plane failures take precedence over availability symptoms because they invalidate operator interpretation |

Additional rules:

- do not downgrade a live incident while `needs_replay=yes` and the quoted `replay_command=` has not been attempted or verified;
- do not downgrade a live incident while `needs_rollback=yes` and the rollback decision is still under discussion;
- if impact is unknown, classify at the higher plausible severity until blast radius is bounded.

---

## Starter alert set

These are the minimum launch-blocker-oriented alert families from the gap matrix.

| Signal | Trigger heuristic | Default severity | Default `needs_replay` | Default `needs_rollback` | Required responder action |
| --- | --- | --- | --- | --- | --- |
| `node-down` | node health endpoint or scrape target missing for 2 consecutive windows | `sev1` | `yes` | `no` by default; promote to `yes` if outage follows deploy, config change, or failed recovery action | Page on-call, capture current evidence paths, confirm whether failure is process, host, or network reachability. |
| `sync-lag` | committed/observed height progress stalls or lag remains above operator threshold for 2 consecutive windows | `sev1` | `yes` | `yes` | Page on-call, capture lagging node identity, and attach recovery / replay evidence pointers. |
| `replay-failure` | recovery / replay drill or emitted evidence cannot be reproduced with emitted `replay_command=` | `sev1` | `yes` | `yes` until rollback path is explicitly ruled out by the incident lead | Page on-call and classify handoff as incomplete until replay/evidence alignment is restored. |
| `rpc-unhealthy` | rpc health/readiness path fails for 2 consecutive windows or query error rate dominates the healthy baseline | `sev1` | `yes` | `no` by default; promote to `yes` if the regression began after deploy, schema change, or read-model cutover | Page on-call, capture failing endpoint, and attach current rollback / replay context. |
| `worker-failure` | worker receipts/submissions stall or repeated worker execution failures persist for 2 consecutive windows | `sev1` | `yes` | `no` by default; promote to `yes` if queue drain, receipt replay, or recent worker release cannot safely stabilize the flow | Page on-call, capture affected worker ids / queues, and link the active worker runbook or receipt evidence. |
| `oracle-anomaly` | use the severity rules from `trillionnium/docs/runbooks/oracle-observability-alerts.md` | inherited | inherited from the oracle runbook | inherited from the oracle runbook; do not drop the shared field in the ticket/page payload | Use the oracle runbook as source of truth; preserve the shared label block here. |
| `bridge-anomaly` | bridge relay or settlement heartbeat stalls for 2 consecutive windows | `sev2` by default | `no` by default; promote to `yes` if settlement integrity or replay evidence is in doubt | `no` by default; promote to `yes` if settlement integrity or replay evidence is in doubt | Open incident, gather evidence, and promote if settlement integrity or operator trust is at risk. |
| `contract-drift` | dashboard math / label mapping / evidence fields drift so the signal cannot be trusted | `sev0` | `yes` | `yes` | Page immediately and freeze automated interpretation until corrected. |

Threshold rules:

- consecutive windows must align with the slowest shared dashboard rollup used by operators;
- default `needs_replay=yes` for every `sev0` / `sev1` row unless a stricter service-specific runbook overrides it explicitly;
- if observability output and emitted evidence artifacts disagree, override any lower classification to `sev0`;
- if a page fires without the full shared label block (`plane`, `service`, `severity`, `signal`, `needs_replay`, `needs_rollback`, and `first_stop`), treat the incident as under-specified;
- for `service=oracle`, also treat the incident as under-specified if `verdict=` is missing, even when the shared label block above is otherwise present;
- if `needs_rollback=yes`, the ticket/page must quote the current `rollback_command=` verbatim or mark it as `unknown` rather than leaving the field implicit.

---

## Minimum dashboard bundle

For mainnet rehearsal, keep one small dashboard pack with stable panel names.

### 1. Node liveness / height progress

Show:

- scrape / health availability
- observed height
- committed height
- sync lag or stalled-height indicator

Why:

- covers `node-down` and `sync-lag`
- gives operators one first-stop panel for network/runtime health

### 2. Consensus instability / rollback pressure

Show:

- `rollback_total`
- `bft_round_change_total`
- `bft_round_change_backoff_total_ms`
- `bft_round_change_backoff_wall_share_ppm`
- `bft_round_change_backoff_share_ppm`
  - treat `bft_round_change_backoff_wall_share_ppm` as the descriptive wall-clock share field and `bft_round_change_backoff_share_ppm` as the grep-stable compatibility alias; today they intentionally carry the same value.
- `bft_leader_missed_total`
- `bft_double_vote_total`
- `bft_auth_reject_bad_sig_total`
- `bft_auth_reject_replay_total`
- `bft_auth_reject_stale_total`
- `bft_auth_reject_stale_nonce_total`
  - treat `bft_auth_reject_stale_nonce_total` as the descriptive stale-nonce counter and `bft_auth_reject_stale_total` as the grep-stable compatibility alias until the broader metrics contract is explicitly split.

Why:

- turns node-level instability into one visible operator surface
- keeps bad-signature, replay, and stale-auth churn visible together, using the same emitted summary fields that `trnm-node` already exports for operator-facing consensus summaries
- links incident review to replay/recovery instead of guesswork

### 3. RPC health / read surface

Show:

- rpc health/readiness status
- query success vs failure trend
- latency trend for the minimum Day-1 read path

Why:

- covers `rpc-unhealthy`
- protects the public read-model / explorer perimeter called out in the blocker board

### 4. Worker execution / receipt flow

Show:

- worker pickup rate
- submission / receipt success rate
- retry / exhaustion / timeout trend

Why:

- covers `worker-failure`
- gives responders a single panel for queueing vs execution vs submission diagnosis

### 5. Evidence / replay integrity

Show or annotate:

- latest `summary.txt` path
- latest `manifest.txt` path when present
- whether `replay_command=` and `rollback_command=` were captured
- whether identity fields match the assigned worktree/branch for the active rehearsal

Why:

- closes the gap between dashboards and incident evidence
- makes `replay-failure` and `contract-drift` visible without relying on shell history

### 6. Service-specific drill-downs

At minimum link out to:

- oracle dashboard bundle from `trillionnium/docs/runbooks/oracle-observability-alerts.md`
- bridge settlement / relay drill-down: settlement heartbeat trend, relay/backlog evidence, and the matching release evidence block from `trillionnium/docs/runbooks/local-release-evidence.md`
- recovery / WAL runbook from `trillionnium/docs/runbooks/bft-checkpoint-wal-recovery.md`
- release evidence runbook from `trillionnium/docs/runbooks/local-release-evidence.md`

### 7. Bridge relay / settlement integrity

Show or annotate:

- bridge relay heartbeat trend
- settlement loop success vs failure trend
- latest settlement evidence pointer or release `summary.txt` / `manifest.txt` when present
- whether `replay_command=` and `rollback_command=` were captured when settlement integrity is in doubt

Why:

- gives `bridge-anomaly` one stable first-stop panel instead of a generic service-specific placeholder
- keeps settlement trust incidents tied to evidence and rollback state, not only to liveness graphs

### 8. First-stop routing table

Use one append-stable routing table so the first responder does not have to guess which panel or artifact to open first.

| Service | Signal | Open first | Immediately verify | Why this first stop exists |
| --- | --- | --- | --- | --- |
| `node` | `node-down` | **Node liveness / height progress** | scrape/health availability, current host reachability note, latest `summary_path` / `manifest_path` if the outage happened during rehearsal | distinguishes process crash, host/network loss, and false scrape gaps before responders chase replay noise |
| `node` | `sync-lag` | **Node liveness / height progress** | committed vs observed height trend, lagging node id, latest `replay_command=` / recovery evidence pointer | keeps sync incidents tied to one concrete lagging node and one replay/recovery trail |
| `node` | `replay-failure` | **Evidence / replay integrity** | `replay_command=`, `rollback_command=`, `git_worktree_path=`, `git_worktree_branch_ref_match=` | replay failures are evidence-plane incidents first, not graph-reading exercises |
| `node` | `node-down` + rollback/backoff churn | **Consensus instability / rollback pressure** | `rollback_total`, round-change/backoff trend, leader-miss or auth-replay spike, and the latest recovery evidence pointer | gives responders one explicit first stop when availability symptoms coincide with rollback pressure instead of forcing them to infer consensus stress from unrelated panels |
| `rpc` | `rpc-unhealthy` | **RPC health / read surface** | failing endpoint, query success/failure trend, latest rollback/replay pointer if the failure followed deploy or rehearsal | preserves the public read surface as its own first-class operator plane |
| `worker` | `worker-failure` | **Worker execution / receipt flow** | affected worker ids/queues, retry/exhaustion trend, linked worker receipt evidence | separates queue starvation from execution or submission failure before escalation |
| `oracle` | `oracle-anomaly` | **Oracle-specific drill-down** | labels from `trillionnium/docs/runbooks/oracle-observability-alerts.md`, matching `severity`, `needs_replay`, and evidence pointers | oracle triage already has a service-specific contract; use it without dropping the shared labels |
| `bridge` | `bridge-anomaly` | **Bridge relay / settlement integrity** | bridge relay/settlement heartbeat evidence, settlement blast radius, replay/rollback pointers if integrity is in doubt | bridge incidents often start as sev2 but can promote quickly when settlement trust is threatened |
| `any` | `contract-drift` | **Evidence / replay integrity** | label block completeness, dashboard math/field drift, `truth_source=`, `evidence_scope=`, identity-match fields | if the contract is drifting, operators must stop trusting the dashboard before anything else |

Routing rules:

- if multiple signals fire together, start with the highest-severity row; if severities tie, prefer `contract-drift` → `replay-failure` → availability/performance signals;
- if `node-down` or `sync-lag` fires together with visible rollback, round-change backoff, leader-miss, or auth-replay churn, switch the first stop from **Node liveness / height progress** to **Consensus instability / rollback pressure** before deciding whether the issue is pure host loss or active consensus stress;
- if the chosen first-stop panel lacks the fields listed under **Immediately verify**, classify the handoff as incomplete and add those missing fields to the ticket/page before reassignment;
- for `service=oracle`, do not reassign the incident until `verdict=` is restored beside the shared label block, because oracle routing depends on the subtype as well as the shared severity/signal fields;
- if the signal is `oracle-anomaly` but the shared label block is missing, restore the shared block first and then continue with the oracle-specific runbook.

## Dashboard annotation minimum

For every `sev0` / `sev1` page, screenshot, or dashboard share link, attach one compact annotation block beside the graph instead of relying on panel titles alone.
This keeps the first-stop dashboard surface semantically aligned with the ticket/handoff text.

Minimum annotation fields:

- `plane=observability`
- `service=<node|rpc|worker|oracle|bridge|any>`
- `severity=<sev0|sev1|sev2|sev3>`
- `signal=<node-down|sync-lag|replay-failure|rpc-unhealthy|worker-failure|oracle-anomaly|bridge-anomaly|contract-drift>`
- `verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|contract-drift|n/a>`
- `needs_replay=<yes|no>`
- `needs_rollback=<yes|no>`
- `first_stop=<stable-panel-name-from-this-runbook|unknown>`
- `truth_source=<verbatim emitted value|unknown>`
- `evidence_scope=<verbatim emitted value|unknown>`
- `summary_path=<abs-path|unknown>`
- `manifest_path=<abs-path|unknown>`
- `git_worktree_path=<abs-path|unknown>`
- `git_worktree_branch_ref=<refs/heads/...|unknown>`
- `git_expected_worktree_branch_ref=<refs/heads/...|unknown>`
- `git_worktree_branch_ref_match=<true|false|unknown>`
- `replay=<present|missing>`
- `rollback=<present|missing>`

Annotation rules:

- the `first_stop=` value must exactly match one stable panel name from this runbook; do not invent shortened aliases in screenshots or share links;
- preserve `needs_replay=` / `needs_rollback=` alongside `replay=` / `rollback=` so responders can distinguish required evidence actions from merely missing pointers;
- preserve `truth_source=` / `evidence_scope=` from emitted artifacts when present so dashboard annotations stay semantically aligned with the incident evidence block and the `contract-drift` routing path;
- preserve `git_worktree_path=` / `git_worktree_branch_ref=` / `git_expected_worktree_branch_ref=` / `git_worktree_branch_ref_match=` when emitted so responders can reject identity-drifted evidence before trusting the graph;
- if the dashboard tool cannot render all fields inline, put the missing fields into the linked incident/ticket body and treat the dashboard share as incomplete until that link exists;
- if `needs_rollback=yes` but `rollback=missing`, classify the dashboard annotation as insufficient until the page or linked ticket quotes the current `rollback_command=` or explicitly records it as `unknown`;
- if `replay=missing` and `rollback=missing` during a live `sev0` / `sev1` incident, classify the dashboard annotation as insufficient even if the graph looks obvious;
- for `service=oracle`, also preserve `verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|ingest-latency|contract-drift>` next to the shared fields so the oracle-specific subtype is visible in the dashboard layer too.

Example annotation lines:

- `plane=observability service=rpc severity=sev1 signal=rpc-unhealthy verdict=n/a needs_replay=yes needs_rollback=no first_stop="RPC health / read surface" truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=missing`
- `plane=observability service=node severity=sev1 signal=node-down verdict=n/a needs_replay=yes needs_rollback=yes first_stop="Consensus instability / rollback pressure" truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=present`
- `plane=observability service=worker severity=sev1 signal=worker-failure verdict=n/a needs_replay=yes needs_rollback=no first_stop="Worker execution / receipt flow" truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=missing`
- `plane=observability service=oracle severity=sev1 signal=oracle-anomaly verdict=quorum-collapse needs_replay=yes needs_rollback=no first_stop="Oracle-specific drill-down" truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=missing`
- `plane=observability service=bridge severity=sev2 signal=bridge-anomaly verdict=n/a needs_replay=no needs_rollback=no first_stop="Bridge relay / settlement integrity" truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=missing rollback=missing`

---

## Minimum incident evidence block

Every `sev0` / `sev1` incident should preserve one compact evidence block:

- `plane`: `observability`
- `service`: `<node|rpc|worker|oracle|bridge|any>`
- `severity`: `<sev0|sev1|sev2|sev3>`
- `signal`: `<node-down|sync-lag|replay-failure|rpc-unhealthy|worker-failure|oracle-anomaly|bridge-anomaly|contract-drift>`
- `verdict`: `<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|ingest-latency|contract-drift|n/a>`
- `needs_replay`: `<yes|no>`
- `needs_rollback`: `<yes|no>`
- `first_stop_panel`: `<Node liveness / height progress|Consensus instability / rollback pressure|RPC health / read surface|Worker execution / receipt flow|Evidence / replay integrity|Oracle-specific drill-down|Bridge relay / settlement integrity|unknown>`
- `summary_line`: `<one-line operator summary>`
- `summary_path`: `<abs-path-to-summary.txt|unknown>`
- `manifest_path`: `<abs-path-to-manifest.txt|unknown>`
- `truth_source`: `<verbatim emitted value|unknown>`
- `evidence_scope`: `<verbatim emitted value|unknown>`
- `rollback_command`: `<verbatim emitted value|unknown>`
- `replay_command`: `<verbatim emitted value|unknown>`
- `git_worktree_path`: `<verbatim emitted value|unknown>`
- `git_worktree_branch_ref`: `<verbatim emitted value|unknown>`
- `git_expected_worktree_branch_ref`: `<verbatim emitted value|unknown>`
- `git_worktree_branch_ref_match`: `<true|false|unknown>`

Rules:

1. Prefer emitted fields from generated artifacts over hand-written shell summaries.
2. Quote `rollback_command=` / `replay_command=` verbatim; do not rewrite them.
3. Set `verdict=n/a` for non-oracle incidents; for `service=oracle`, preserve the oracle runbook subtype instead of dropping it.
4. Set `first_stop_panel=` to the exact stable panel name from the routing table above; use `unknown` rather than inventing an ad-hoc alias.
5. If `signal=contract-drift`, set `first_stop_panel="Evidence / replay integrity"` even when the symptom first appeared on a service-specific dashboard; observability-contract failures route to evidence integrity before service-local graphs.
6. If the worktree/branch identity fields are missing or mismatched during an incident, classify as at least `sev0` until reconciled.
7. If both replay and rollback pointers are absent, the handoff is incomplete even if the graph looks obvious.
8. When both `summary.txt` and `manifest.txt` exist, prefer `./scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root <ticket-or-rehearsal-worktree> --expected-branch-ref <ticket-or-rehearsal-branch>` so `summary_path=`, `manifest_path=`, `git_worktree_branch_ref=`, and `git_worktree_branch_ref_match=` are populated fail-closed against the assigned worktree/branch rather than whatever branch happens to be checked out locally.

Quick extraction template for responders:

```bash
./scripts/v2/extract_release_handoff_fields.sh \
  --summary-path <abs-path-to-summary.txt> \
  --manifest-path <abs-path-to-manifest.txt> \
  --expected-worktree-root <ticket-or-rehearsal-worktree> \
  --expected-branch-ref <ticket-or-rehearsal-branch>
```

Use the emitted fields verbatim in the page/ticket annotation block. If the script reports `git_worktree_branch_ref_match=false`, treat the incident as identity-drifted until the evidence bundle and assigned worktree/branch are reconciled.

---

## Operator summary line template

Use one compact line in pages, tickets, and dashboard snapshots:

- `plane=observability service=<service> severity=<sevX> signal=<signal> verdict=<oracle-subtype|n/a> needs_replay=<yes|no> needs_rollback=<yes|no> first_stop=<stable-panel-name|unknown> observed=<what-failed> impact=<blast-radius> truth_source=<value|unknown> evidence_scope=<value|unknown> summary_path=<path|unknown> manifest_path=<path|unknown> git_worktree_path=<path|unknown> git_worktree_branch_ref=<refs/heads/...|unknown> git_expected_worktree_branch_ref=<refs/heads/...|unknown> git_worktree_branch_ref_match=<true|false|unknown> replay=<present|missing> rollback=<present|missing>`

Keep `first_stop=` aligned with the exact stable panel name from the routing table above, copy `truth_source=` / `evidence_scope=` from emitted evidence when present, and preserve the emitted `git_worktree_*` identity fields whenever available so lane-bound evidence can be rejected fail-closed on mismatch. If the transport format cannot safely carry spaces, wrap the panel name in quotes rather than inventing an underscore alias.

Example:

- `plane=observability service=node severity=sev1 signal=sync-lag verdict=n/a needs_replay=yes needs_rollback=yes first_stop="Node liveness / height progress" observed=committed_height_flat impact=one-validator truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=present`
- `plane=observability service=rpc severity=sev1 signal=rpc-unhealthy verdict=n/a needs_replay=yes needs_rollback=no first_stop="RPC health / read surface" observed=healthcheck_failures_rising impact=public-read-path-degraded truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=missing`
- `plane=observability service=worker severity=sev1 signal=worker-failure verdict=n/a needs_replay=yes needs_rollback=no first_stop="Worker execution / receipt flow" observed=receipt_submission_flat impact=one-worker-queue truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=missing`
- `plane=observability service=oracle severity=sev1 signal=oracle-anomaly verdict=quorum-collapse needs_replay=yes needs_rollback=no first_stop="Oracle-specific drill-down" observed=source_cardinality_below_floor impact=price-ingest-degraded truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=missing`
- `plane=observability service=bridge severity=sev2 signal=bridge-anomaly verdict=n/a needs_replay=no needs_rollback=no first_stop="Bridge relay / settlement integrity" observed=settlement_heartbeat_stalled impact=cross-chain-settlement-delayed truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=missing rollback=missing`
- `plane=observability service=any severity=sev0 signal=contract-drift verdict=n/a needs_replay=yes needs_rollback=yes first_stop="Evidence / replay integrity" observed=label_block_mismatch impact=dashboard-routing-untrusted truth_source=local-release-evidence-v1 evidence_scope=release-handoff summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt git_worktree_path=/abs/lane/MN12 git_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_expected_worktree_branch_ref=refs/heads/lane/mn12-alerting-dashboard-incident-sre git_worktree_branch_ref_match=true replay=present rollback=present`

---

## Responder checklist

1. Confirm the shared label block is present, including `needs_replay` and `needs_rollback`; for `service=oracle`, also confirm `verdict=` is preserved.
2. Confirm the active dashboard uses stable panel names from this runbook.
3. Pull `replay_command=` / `rollback_command=` from generated artifacts, not from memory.
4. Confirm `git_worktree_path=`, `git_worktree_branch_ref=`, and `git_expected_worktree_branch_ref=` all match the assigned lane/rehearsal target.
5. If evidence and graphs disagree, escalate to `sev0` and freeze automated interpretation.
6. Link to the service-specific runbook before handing off.

---

## Exit condition for this starter pack

This document is doing its job only if operators can answer all of the following without searching shell scrollback:

- What failed?
- How severe is it?
- Which dashboard should I open first?
- Which replay / rollback command applies?
- Does the evidence actually belong to the assigned worktree/branch?

If any answer still depends on memory or private operator context, the observability plane is still not closed.
