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

---

## Starter alert set

These are the minimum launch-blocker-oriented alert families from the gap matrix.

| Signal | Trigger heuristic | Default severity | Required responder action |
| --- | --- | --- | --- |
| `node-down` | node health endpoint or scrape target missing for 2 consecutive windows | `sev1` | Page on-call, capture current evidence paths, confirm whether failure is process, host, or network reachability. |
| `sync-lag` | committed/observed height progress stalls or lag remains above operator threshold for 2 consecutive windows | `sev1` | Page on-call, capture lagging node identity, and attach recovery / replay evidence pointers. |
| `replay-failure` | recovery / replay drill or emitted evidence cannot be reproduced with emitted `replay_command=` | `sev1` | Page on-call and classify handoff as incomplete until replay/evidence alignment is restored. |
| `rpc-unhealthy` | rpc health/readiness path fails for 2 consecutive windows or query error rate dominates the healthy baseline | `sev1` | Page on-call, capture failing endpoint, and attach current rollback / replay context. |
| `worker-failure` | worker receipts/submissions stall or repeated worker execution failures persist for 2 consecutive windows | `sev1` | Page on-call, capture affected worker ids / queues, and link the active worker runbook or receipt evidence. |
| `oracle-anomaly` | use the severity rules from `docs/runbooks/oracle-observability-alerts.md` | inherited | Use the oracle runbook as source of truth; preserve the shared label block here. |
| `bridge-anomaly` | bridge relay or settlement heartbeat stalls for 2 consecutive windows | `sev2` by default | Open incident, gather evidence, and promote if settlement integrity or operator trust is at risk. |
| `contract-drift` | dashboard math / label mapping / evidence fields drift so the signal cannot be trusted | `sev0` | Page immediately and freeze automated interpretation until corrected. |

Threshold rules:

- consecutive windows must align with the slowest shared dashboard rollup used by operators;
- if observability output and emitted evidence artifacts disagree, override any lower classification to `sev0`;
- if a page fires without `severity`, `signal`, `needs_replay`, and `needs_rollback`, treat the incident as under-specified.

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

---

## Minimum incident evidence block

Every `sev0` / `sev1` incident should preserve one compact evidence block:

- `plane`: `observability`
- `service`: `<node|rpc|worker|oracle|bridge>`
- `severity`: `<sev0|sev1|sev2|sev3>`
- `signal`: `<node-down|sync-lag|replay-failure|rpc-unhealthy|worker-failure|oracle-anomaly|bridge-anomaly|contract-drift>`
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
