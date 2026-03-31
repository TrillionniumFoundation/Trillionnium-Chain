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

- `sample_count=<n> accepted_total=<n> stale=<n> quorum=<n> drift=<n> source_cardinality=<n|unknown> ingest_latency_ms=<n|unknown> verdict=<accepts-stalled|stale-wave|quorum-collapse|drift-anomaly|contract-drift>`

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

## Operator note

These metrics are already guarded by schema/serialization tests in `trnm-rpc` and `trnm-oracle`. Keep alert rules append-stable and prefer adding new metrics over renaming existing ones.
