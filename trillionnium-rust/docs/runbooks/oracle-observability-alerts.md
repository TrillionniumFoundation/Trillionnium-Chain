# Oracle Observability / Alert Hints

This runbook turns the existing oracle validation metrics contract into a small operator-facing alert surface.

## Metric endpoints

`trnm-rpc` test coverage keeps both of these scrape targets stable:

- `/metrics`
- `/oracle/metrics`

## Stable counter/gauge contract

Source of truth: `docs/reports/oracle-metrics-contract.json`

### Counters

- `oracle_stale_reject_total`
  - Meaning: snapshots rejected because a required source timestamp exceeded staleness bounds.
  - Page if: increases continuously while `accepted_total` stays flat.
  - First checks:
    - upstream source timestamps
    - local clock skew / NTP drift
    - feed-specific lag concentrated in one source

- `oracle_quorum_reject_total`
  - Meaning: snapshots rejected because canonicalized unique sources dropped below quorum.
  - Page if: non-zero for consecutive scrape windows or if it dominates `sample_count`.
  - First checks:
    - missing providers / provider auth failures
    - source dedup collapsing to too few unique canonical sources
    - network reachability to upstream sources

- `oracle_drift_reject_total`
  - Meaning: snapshots rejected because one or more sources deviated from the median past threshold.
  - Page if: spikes above stale/quorum rejects, especially with healthy source cardinality.
  - First checks:
    - outlier provider publishing wrong price
    - source normalization / unit mismatch
    - feed migration or symbol mapping drift

- `accepted_total`
  - Meaning: snapshots accepted by the validator.
  - Alert if: stalls while `sample_count` keeps growing.

- `sample_count`
  - Meaning: total snapshots processed.
  - Use as denominator for alert rates.

### Gauges

- `oracle_source_cardinality`
  - Meaning: max canonicalized accepted source cardinality seen in the run.
  - Alert if: drops below expected quorum floor or regresses from recent normal baseline.
  - Caveat: this is a max-over-accepted-snapshots signal, not a per-sample instantaneous gauge.

- `oracle_ingest_latency_ms`
  - Meaning: offline oracle validation bridge elapsed batch duration.
  - Use as trend signal only; it is not the node hot-path latency metric.

## Required invariant

The contract is intentionally conservative:

`accepted_total + oracle_stale_reject_total + oracle_quorum_reject_total + oracle_drift_reject_total == sample_count`

If this conservation rule breaks, treat it as a metrics/schema regression before trusting any rate alert.

## Simple alert heuristics

These are safe starter alerts for mainnet rehearsal.

1. **Oracle accepts stalled**
   - Condition: `sample_count` increases over two scrape windows and `accepted_total` does not.
   - Severity: high.

2. **Staleness rejection wave**
   - Condition: `oracle_stale_reject_total / sample_count` exceeds a small fixed threshold for consecutive windows.
   - Severity: medium/high depending on persistence.

3. **Quorum collapse**
   - Condition: `oracle_quorum_reject_total > 0` for consecutive windows, or `oracle_source_cardinality < configured minimum quorum`.
   - Severity: high.

4. **Drift anomaly**
   - Condition: `oracle_drift_reject_total` spikes while source cardinality remains healthy.
   - Severity: medium/high.

5. **Contract drift**
   - Condition: counter conservation invariant breaks.
   - Severity: critical for observability correctness.

## Incident triage order

1. Check whether `sample_count` is still moving.
2. Compare `accepted_total` vs the three reject counters.
3. Inspect `oracle_source_cardinality` to separate quorum loss from data-quality drift.
4. If rejects are mostly stale, verify time sync and upstream freshness.
5. If rejects are mostly drift, isolate the outlier provider/symbol mapping.
6. If counters do not conserve to `sample_count`, stop relying on alert math and investigate the metrics contract.

## Operator-visible summary template

When opening an incident or handing off between operators, include one compact summary line built only from the stable metric names above.

Minimal template:

- `plane=observability service=oracle severity=<sev0|sev1|sev2|sev3> signal=oracle-anomaly verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|contract-drift> needs_replay=<yes|no> needs_rollback=<yes|no> first_stop=<"Oracle-specific drill-down"|"Evidence / replay integrity"|unknown> sample_count=<n> accepted_total=<n> stale=<n> quorum=<n> drift=<n> source_cardinality=<n|unknown> ingest_latency_ms=<n|unknown> truth_source=<value|unknown> evidence_scope=<value|unknown> summary_path=<path|unknown> manifest_path=<path|unknown> git_worktree_path=<path|unknown> git_worktree_branch_ref=<refs/heads/...|unknown> git_expected_worktree_branch_ref=<refs/heads/...|unknown> git_worktree_branch_ref_match=<true|false|unknown> replay=<present|missing> rollback=<present|missing>`

Use `first_stop="Oracle-specific drill-down"` for normal oracle triage and `first_stop="Evidence / replay integrity"` whenever `verdict=contract-drift` or emitted evidence contradicts dashboard math.

Template rules:

- copy `truth_source=`, `evidence_scope=`, `summary_path=`, and `manifest_path=` from emitted artifacts when present so oracle incidents stay append-stable with the shared observability handoff contract;
- preserve emitted `git_worktree_path=` / `git_worktree_branch_ref=` / `git_expected_worktree_branch_ref=` / `git_worktree_branch_ref_match=` fields when present so rehearsal evidence can be rejected fail-closed on lane mismatch;
- set `replay=<present|missing>` and `rollback=<present|missing>` from emitted `replay_command=` / `rollback_command=` state rather than operator memory;
- if the dashboard or page payload omits these evidence fields, treat the handoff as incomplete until the linked incident body preserves them.

This keeps oracle handoff lines compatible with the shared observability routing contract in `docs/runbooks/mainnet-observability-alerting-starter-pack.md` while still preserving the oracle-specific `verdict`.

## Incident note 最小模板

把下面字段原样抄进告警注释、交接 ticket 或值班 handoff，可避免不同 dashboard 命名不一致时丢上下文：

- `summary_line`: `<直接使用上面的 operator-visible summary line>`
- `sample_count`: `<n>`
- `accepted_total`: `<n>`
- `oracle_stale_reject_total`: `<n>`
- `oracle_quorum_reject_total`: `<n>`
- `oracle_drift_reject_total`: `<n>`
- `oracle_source_cardinality`: `<n|unknown>`
- `oracle_ingest_latency_ms`: `<n|unknown>`
- `conservation_invariant_ok`: `<yes|no>`
- `verdict`: `<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|contract-drift>`
- `first_check`: `<clock-skew|provider-loss|source-dedup-collapse|symbol-mapping-drift|metrics-schema-regression>`

Interpretation hints:

- choose `contract-drift` first if the conservation invariant breaks, even if another reject class is elevated;
- choose `quorum-collapse` over `drift-anomaly` when source cardinality is below quorum floor;
- choose `accepts-stalled` when `sample_count` is still increasing but `accepted_total` is flat.

This keeps pager handoff text append-stable even if dashboards differ across environments.

## Stable incident labels

Use one small label set across page payloads, dashboard share links, and incident tickets.
This closes the last-mile gap where operators agree on the graph but still tag the same incident differently.

Minimum label block:

- `service=oracle`
- `plane=observability`
- `severity=<sev0|sev1|sev2|sev3>`
- `signal=oracle-anomaly`
- `verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|contract-drift>`
- `needs_replay=<yes|no>`
- `needs_rollback=<yes|no>`
- `first_stop=<Oracle-specific drill-down|Evidence / replay integrity|unknown>`

Label rules:

- set `needs_replay=yes` for every `sev0`/`sev1` incident, or whenever evidence and observability disagree;
- set `needs_rollback=yes` only when an emitted `rollback_command=` exists or an operator has explicitly chosen rollback as the active mitigation path;
- keep `first_stop=Oracle-specific drill-down` for normal oracle triage and switch to `Evidence / replay integrity` whenever `verdict=contract-drift` or emitted evidence contradicts dashboard math;
- if a dashboard screenshot/link is shared without the label block, treat the handoff as incomplete even if the graph itself looks obvious.

## Dashboard minimum bundle

For mainnet rehearsal, treat the following as the smallest acceptable oracle dashboard bundle.
Keep panel titles stable so alerts, screenshots, and handoff notes refer to the same surface.

1. **Acceptance vs rejects**
   - Plot: `accepted_total`, `oracle_stale_reject_total`, `oracle_quorum_reject_total`, `oracle_drift_reject_total`
   - Why: establishes whether the incident is an accepts stall, stale wave, quorum collapse, or drift anomaly.

2. **Sample conservation**
   - Plot: `sample_count` together with the derived sum `accepted_total + oracle_stale_reject_total + oracle_quorum_reject_total + oracle_drift_reject_total`
   - Why: makes `contract-drift` visible without requiring operators to do arithmetic from memory.

3. **Source cardinality vs quorum floor**
   - Plot: `oracle_source_cardinality` plus the configured quorum floor annotation
   - Why: separates provider loss / dedup collapse from pure data-quality drift.

4. **Ingest latency trend**
   - Plot: `oracle_ingest_latency_ms`
   - Why: keeps batch-duration regressions visible even when acceptance has not yet stalled.

Dashboard annotation rules:

- annotate the configured quorum floor on any panel that renders `oracle_source_cardinality`;
- annotate the incident `severity`, `verdict`, `needs_replay`, and `needs_rollback` on `sev0` / `sev1` screenshots or dashboard share links;
- keep `first_stop=` aligned with the shared observability routing contract: use `first_stop="Oracle-specific drill-down"` for normal oracle triage and switch to `first_stop="Evidence / replay integrity"` whenever `verdict=contract-drift` or emitted evidence contradicts dashboard math;
- when linking a dashboard snapshot into an incident ticket, include the `summary_line` beside it so the image and ticket stay semantically aligned;
- if the dashboard tool cannot render the full shared block inline, copy the missing fields (`needs_replay`, `needs_rollback`, `first_stop`, `truth_source`, `evidence_scope`, `summary_path`, `manifest_path`, `git_worktree_path`, `git_worktree_branch_ref`, `git_expected_worktree_branch_ref`, `git_worktree_branch_ref_match`) into the linked incident body and treat the screenshot/share link as incomplete until that link exists.

## Starter alert threshold matrix

Use this as the smallest threshold contract for mainnet rehearsal.
The goal is not perfect tuning; it is to stop dashboards, pages, and incident tickets from drifting into different severity vocabularies.

| Signal | Trigger heuristic | Default severity | Default `needs_replay` | Default `needs_rollback` | Required responder action |
| --- | --- | --- | --- | --- | --- |
| `contract-drift` | `sample_count` diverges from `accepted_total + oracle_stale_reject_total + oracle_quorum_reject_total + oracle_drift_reject_total` for 2 consecutive scrapes | `sev0` | `yes` | `yes` | Page immediately, freeze automated interpretation, and open an incident with evidence pointers. |
| `accepts-stalled` | `sample_count` increases while `accepted_total` stays flat for 2 consecutive windows | `sev1` | `yes` | `yes` until rollback is explicitly ruled out by the incident lead | Page on-call and attach `replay_command=` / `rollback_command=` state. |
| `quorum-collapse` | `oracle_source_cardinality` stays below quorum floor for 2 consecutive windows | `sev1` | `yes` | `no` by default; promote to `yes` if provider rollback, config rollback, or release rollback becomes the active mitigation path | Page on-call and confirm whether provider loss or dedup collapse is active. |
| `stale-wave` | `oracle_stale_reject_total` dominates rejects for 3 consecutive windows while source cardinality stays at/above quorum floor | `sev2` | `no` by default; promote to `yes` if evidence and observability disagree during mitigation | `no` by default; promote to `yes` if stale data follows a release/config change and rollback is selected as mitigation | Investigate in the active on-call window and promote if acceptance impact appears. |
| `drift-anomaly` | `oracle_drift_reject_total` rises for 3 consecutive windows while source cardinality stays healthy | `sev2` | `no` by default; promote to `yes` if evidence and observability disagree during mitigation | `no` by default; promote to `yes` if rollback is chosen to restore the last trusted oracle policy/config surface | Investigate drift source, capture summary line, and promote if spread persists. |
| `ingest-latency` | `oracle_ingest_latency_ms` rises for 3 consecutive windows without acceptance impact | `sev3` | `no` | `no` | Record in dashboard notes / handoff; no page by default. |

Threshold rules:

- consecutive windows should map to the dashboard's stable rollup interval; if multiple dashboards exist, use the slowest shared rollup when paging;
- default `needs_replay=yes` for every `sev0` / `sev1` row unless the responder has already reconciled observability with emitted evidence and the service-specific runbook says otherwise;
- if observability data and emitted evidence artifacts disagree, override any lower threshold and classify as `sev0`;
- if a page fires without the matching `severity` / `signal` / `verdict` / `needs_replay` / `needs_rollback` label block, treat the incident as under-specified until the labels are added;
- if `needs_rollback=yes`, the page/ticket should quote the current emitted `rollback_command=` verbatim or mark it as `unknown` instead of leaving rollback state implicit.

## Severity mapping

Use one small severity vocabulary across dashboards, pages, and incident tickets.
This avoids the current blocker where alert thresholds exist locally but operators still classify incidents differently.

- `sev0`
  - Meaning: observability plane itself is untrustworthy or the chain cannot be safely operated without immediate human intervention.
  - Examples:
    - `contract-drift` because the conservation invariant broke
    - repeated page-worthy oracle failures together with missing/contradictory evidence artifacts
  - Expected action: page immediately, freeze automated interpretation of oracle alerts until evidence is revalidated.

- `sev1`
  - Meaning: mainnet-impacting degradation is active or highly likely.
  - Examples:
    - `accepts-stalled` persists while `sample_count` keeps moving
    - `quorum-collapse` persists across consecutive windows
  - Expected action: page on-call, open incident, capture replay/rollback pointers.

- `sev2`
  - Meaning: degraded but still attributable; operators have time to confirm the blast radius before escalation.
  - Examples:
    - sustained `stale-wave`
    - `drift-anomaly` with healthy source cardinality but rising reject ratio
  - Expected action: investigate within the active on-call window and promote to `sev1` if persistence or spread increases.

- `sev3`
  - Meaning: informative or early-warning signal only.
  - Examples:
    - one-off reject blip that self-recovers
    - ingest latency trend drift without acceptance impact
  - Expected action: record in dashboard notes or shift handoff; no page by default.

## Replay / rollback linkage for incidents

Every `sev0`/`sev1` incident should carry one evidence pointer block so responders do not have to reconstruct replay state from memory.
Prefer verbatim fields emitted by existing evidence scripts over hand-written shell summaries.

Minimal incident evidence block:

- `service`: `oracle`
- `plane`: `observability`
- `severity`: `<sev0|sev1|sev2|sev3>`
- `signal`: `oracle-anomaly`
- `verdict`: `<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|contract-drift>`
- `needs_replay`: `<yes|no>`
- `needs_rollback`: `<yes|no>`
- `first_stop_panel`: `<Oracle-specific drill-down|Evidence / replay integrity|unknown>`
- `summary_line`: `<operator-visible summary line>`
- `truth_source`: `<value copied from summary.txt/manifest.txt when present>`
- `evidence_scope`: `<value copied from summary.txt/manifest.txt when present>`
- `summary_path`: `<abs-path-to-summary.txt|unknown>`
- `manifest_path`: `<abs-path-to-manifest.txt|unknown>`
- `rollback_command`: `<verbatim emitted value|unknown>`
- `replay_command`: `<verbatim emitted value|unknown>`
- `git_worktree_path`: `<verbatim emitted value|unknown>`
- `git_worktree_branch_ref`: `<verbatim emitted value|unknown>`
- `git_expected_worktree_branch_ref`: `<verbatim emitted value|unknown>`
- `git_worktree_branch_ref_match`: `<true|false|unknown>`

Responder rules:

1. Prefer the exact `rollback_command=` / `replay_command=` emitted by generated artifacts.
2. Keep `signal=oracle-anomaly` in every page/ticket/dashboard link, and use `verdict=` only for the oracle-specific subtype.
3. Set `first_stop_panel=Oracle-specific drill-down` for normal oracle triage; switch to `Evidence / replay integrity` when `verdict=contract-drift` or evidence/metrics disagree.
4. If `truth_source=` or `evidence_scope=` says the artifact is local or historical-only, do not present it as public-mainnet proof.
5. If the incident page lacks both replay and rollback pointers, classify the handoff as incomplete and keep the ticket at least `sev2` until fixed.
6. If `git_worktree_path=` / `git_worktree_branch_ref=` are missing or mismatched during rehearsal, escalate to at least `sev0` until identity is reconciled.
7. If observability data and replay evidence disagree, treat that as `sev0` until the metrics contract or evidence bundle is reconciled.

## Operator note

These metrics are already guarded by schema/serialization tests in `trnm-rpc` and `trnm-oracle`. Keep alert rules append-stable and prefer adding new metrics over renaming existing ones.
