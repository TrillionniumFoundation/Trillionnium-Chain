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
- `docs/runbooks/local-release-evidence.md`
- `docs/runbooks/bft-checkpoint-wal-recovery.md`
- `docs/runbooks/oracle-observability-alerts.md`

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
| `service` | `node`, `rpc`, `worker`, `oracle`, `bridge` | Preserves one cross-service routing surface. |
| `severity` | `sev0`, `sev1`, `sev2`, `sev3` | Prevents page/ticket/dashboard severity drift. |
| `signal` | `node-down`, `sync-lag`, `replay-failure`, `rpc-unhealthy`, `worker-failure`, `oracle-anomaly`, `bridge-anomaly`, `contract-drift` | Keeps alert families stable enough for paging and dashboard links. |
| `needs_replay` | `yes`, `no` | Forces responders to distinguish evidence-required incidents from pure telemetry noise. |
| `needs_rollback` | `yes`, `no` | Preserves rollback intent as an explicit operator decision, not tribal knowledge. |

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
- `service=<node|rpc|worker|oracle|bridge>`
- `severity=<sev0|sev1|sev2|sev3>`
- `signal=<node-down|sync-lag|replay-failure|rpc-unhealthy|worker-failure|oracle-anomaly|bridge-anomaly|contract-drift>`
- `needs_replay=<yes|no>`
- `needs_rollback=<yes|no>`

Rules:

- `needs_replay=yes` for every `sev0` / `sev1` incident.
- `needs_rollback=yes` only when a concrete emitted `rollback_command=` exists or rollback is the active mitigation choice.
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

| Signal | Trigger heuristic | Default severity | Default `needs_rollback` | Required responder action |
| --- | --- | --- | --- | --- |
| `node-down` | node health endpoint or scrape target missing for 2 consecutive windows | `sev1` | `no` by default; promote to `yes` if outage follows deploy, config change, or failed recovery action | Page on-call, capture current evidence paths, confirm whether failure is process, host, or network reachability. |
| `sync-lag` | committed/observed height progress stalls or lag remains above operator threshold for 2 consecutive windows | `sev1` | `yes` | Page on-call, capture lagging node identity, and attach recovery / replay evidence pointers. |
| `replay-failure` | recovery / replay drill or emitted evidence cannot be reproduced with emitted `replay_command=` | `sev1` | `yes` until rollback path is explicitly ruled out by the incident lead | Page on-call and classify handoff as incomplete until replay/evidence alignment is restored. |
| `rpc-unhealthy` | rpc health/readiness path fails for 2 consecutive windows or query error rate dominates the healthy baseline | `sev1` | `no` by default; promote to `yes` if the regression began after deploy, schema change, or read-model cutover | Page on-call, capture failing endpoint, and attach current rollback / replay context. |
| `worker-failure` | worker receipts/submissions stall or repeated worker execution failures persist for 2 consecutive windows | `sev1` | `no` by default; promote to `yes` if queue drain, receipt replay, or recent worker release cannot safely stabilize the flow | Page on-call, capture affected worker ids / queues, and link the active worker runbook or receipt evidence. |
| `oracle-anomaly` | use the severity rules from `docs/runbooks/oracle-observability-alerts.md` | inherited | inherited from the oracle runbook; do not drop the shared field in the ticket/page payload | Use the oracle runbook as source of truth; preserve the shared label block here. |
| `bridge-anomaly` | bridge relay or settlement heartbeat stalls for 2 consecutive windows | `sev2` by default | `no` by default; promote to `yes` if settlement integrity or replay evidence is in doubt | Open incident, gather evidence, and promote if settlement integrity or operator trust is at risk. |
| `contract-drift` | dashboard math / label mapping / evidence fields drift so the signal cannot be trusted | `sev0` | `yes` | Page immediately and freeze automated interpretation until corrected. |

Threshold rules:

- consecutive windows must align with the slowest shared dashboard rollup used by operators;
- if observability output and emitted evidence artifacts disagree, override any lower classification to `sev0`;
- if a page fires without `severity`, `signal`, `needs_replay`, and `needs_rollback`, treat the incident as under-specified;
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
- `bft_leader_missed_total`
- `bft_double_vote_total`
- `bft_auth_reject_replay_total`

Why:

- turns node-level instability into one visible operator surface
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

- oracle dashboard bundle from `docs/runbooks/oracle-observability-alerts.md`
- recovery / WAL runbook from `docs/runbooks/bft-checkpoint-wal-recovery.md`
- release evidence runbook from `docs/runbooks/local-release-evidence.md`

### 7. First-stop routing table

Use one append-stable routing table so the first responder does not have to guess which panel or artifact to open first.

| Service | Signal | Open first | Immediately verify | Why this first stop exists |
| --- | --- | --- | --- | --- |
| `node` | `node-down` | **Node liveness / height progress** | scrape/health availability, current host reachability note, latest `summary_path` / `manifest_path` if the outage happened during rehearsal | distinguishes process crash, host/network loss, and false scrape gaps before responders chase replay noise |
| `node` | `sync-lag` | **Node liveness / height progress** | committed vs observed height trend, lagging node id, latest `replay_command=` / recovery evidence pointer | keeps sync incidents tied to one concrete lagging node and one replay/recovery trail |
| `node` | `replay-failure` | **Evidence / replay integrity** | `replay_command=`, `rollback_command=`, `git_worktree_path=`, `git_worktree_branch_ref_match=` | replay failures are evidence-plane incidents first, not graph-reading exercises |
| `rpc` | `rpc-unhealthy` | **RPC health / read surface** | failing endpoint, query success/failure trend, latest rollback/replay pointer if the failure followed deploy or rehearsal | preserves the public read surface as its own first-class operator plane |
| `worker` | `worker-failure` | **Worker execution / receipt flow** | affected worker ids/queues, retry/exhaustion trend, linked worker receipt evidence | separates queue starvation from execution or submission failure before escalation |
| `oracle` | `oracle-anomaly` | **Oracle-specific drill-down** | labels from `docs/runbooks/oracle-observability-alerts.md`, matching `severity`, `needs_replay`, and evidence pointers | oracle triage already has a service-specific contract; use it without dropping the shared labels |
| `bridge` | `bridge-anomaly` | **Service-specific drill-down** | bridge relay/settlement heartbeat evidence, settlement blast radius, replay/rollback pointers if integrity is in doubt | bridge incidents often start as sev2 but can promote quickly when settlement trust is threatened |
| `any` | `contract-drift` | **Evidence / replay integrity** | label block completeness, dashboard math/field drift, `truth_source=`, `evidence_scope=`, identity-match fields | if the contract is drifting, operators must stop trusting the dashboard before anything else |

Routing rules:

- if multiple signals fire together, start with the highest-severity row; if severities tie, prefer `contract-drift` → `replay-failure` → availability/performance signals;
- if the chosen first-stop panel lacks the fields listed under **Immediately verify**, classify the handoff as incomplete and add those missing fields to the ticket/page before reassignment;
- if the signal is `oracle-anomaly` but the shared label block is missing, restore the shared block first and then continue with the oracle-specific runbook.

---

## Minimum incident evidence block

Every `sev0` / `sev1` incident should preserve one compact evidence block:

- `plane`: `observability`
- `service`: `<node|rpc|worker|oracle|bridge>`
- `severity`: `<sev0|sev1|sev2|sev3>`
- `signal`: `<node-down|sync-lag|replay-failure|rpc-unhealthy|worker-failure|oracle-anomaly|bridge-anomaly|contract-drift>`
- `needs_replay`: `<yes|no>`
- `needs_rollback`: `<yes|no>`
- `summary_line`: `<one-line operator summary>`
- `summary_path`: `<abs-path-to-summary.txt|unknown>`
- `manifest_path`: `<abs-path-to-manifest.txt|unknown>`
- `truth_source`: `<verbatim emitted value|unknown>`
- `evidence_scope`: `<verbatim emitted value|unknown>`
- `rollback_command`: `<verbatim emitted value|unknown>`
- `replay_command`: `<verbatim emitted value|unknown>`
- `git_worktree_path`: `<verbatim emitted value|unknown>`
- `git_worktree_branch_ref`: `<verbatim emitted value|unknown>`
- `git_worktree_branch_ref_match`: `<true|false|unknown>`

Rules:

1. Prefer emitted fields from generated artifacts over hand-written shell summaries.
2. Quote `rollback_command=` / `replay_command=` verbatim; do not rewrite them.
3. If the worktree/branch identity fields are missing or mismatched during an incident, classify as at least `sev0` until reconciled.
4. If both replay and rollback pointers are absent, the handoff is incomplete even if the graph looks obvious.

---

## Operator summary line template

Use one compact line in pages, tickets, and dashboard snapshots:

- `service=<service> severity=<sevX> signal=<signal> needs_replay=<yes|no> needs_rollback=<yes|no> observed=<what-failed> impact=<blast-radius> summary_path=<path|unknown> manifest_path=<path|unknown> replay=<present|missing> rollback=<present|missing>`

Example:

- `service=node severity=sev1 signal=sync-lag needs_replay=yes needs_rollback=yes observed=committed_height_flat impact=one-validator summary_path=/abs/run/health/evidence-20260331/summary.txt manifest_path=/abs/release/rc-20260331/manifest.txt replay=present rollback=present`

---

## Responder checklist

1. Confirm the shared label block is present, including `needs_replay` and `needs_rollback`.
2. Confirm the active dashboard uses stable panel names from this runbook.
3. Pull `replay_command=` / `rollback_command=` from generated artifacts, not from memory.
4. Confirm `git_worktree_path=` / `git_worktree_branch_ref=` match the assigned lane/rehearsal target.
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
