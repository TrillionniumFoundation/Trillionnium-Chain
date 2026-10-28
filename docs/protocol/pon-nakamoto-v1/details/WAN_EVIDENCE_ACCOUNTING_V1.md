# Independent WAN evidence accounting v1

This is the PN5 reporting boundary for work package 5 in the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
No independent WAN campaign has been started by this implementation. Local
processes, multiple ports, different usernames or multiple machines controlled
by one administrator do not meet the existing independence requirement.

The existing [performance acceptance](PERFORMANCE_ACCEPTANCE.md) and
[Cell availability and repair contract](CELL_P2P_V1.md) retain authority over
the required cohorts and thresholds. This reader does not relax them or set
new favorable service objectives after seeing outcomes.

## Preregister before starting

The campaign needs at least three independently administered operators and
failure domains, at least 72 hours of real operation, source and binary
identities for Chain and Hepta, and a signed external threat/fault/load plan.
Each operator supplies authenticated endpoint and administrative-control
evidence. Hosting in three regions is insufficient evidence of three
administrators. Confirm transport and independent monitoring credentials
through the original owners; this implementation neither creates credentials
nor contacts operators.

Freeze every named cohort, offered workload, scheduled operation, unique
original operation ID, confirmation depth, deadline, minimum sample size,
resource limits, fault schedule, repair/retention obligations, no-update
policy and stopping rule. Include the original depleted-budget hostile
cohorts, new-node/history/reorg/restart, publisher and replica losses,
corrupt/slow peers, and complete-model retrieval-to-inference measures.
The maximum timestamp in a JSON file is not evidence that real time elapsed.

## Confirmation accounting reader

`scripts/pon_wan_evidence.py` accepts a `trnm-wan-preregistration-v1` JSON
manifest and newline-delimited original observation records. The manifest
contains:

- `start_unix_ms`, `end_unix_ms`, `confirmation_depth` and SHA-256 references
  for `chain_source_sha256`, `hepta_source_sha256`, `threat_model_sha256`;
- `operators`, with `id`, `administrator`, `failure_domain`, `endpoint` and
  `external_attestation_sha256`;
- `cohorts`, with `id`, `max_confirmation_ms`,
  `minimum_samples_per_operator` and `minimum_timely_ppm`;
- `schedule`, with `id`, `operator`, `cohort`, `operation_sha256` and
  `scheduled_unix_ms` for every original authorized operation.

The operation hash binds the full intent and its unique request/nonce, not
just the requested Cell's content hash. Retrying an original operation or
polling its status retains that same original operation; it cannot become a
second confirmed transaction. Repeated transport attempts belong in the
original operation's raw receipt and resource totals. Traffic-generation
and physical fault records have their own denominators and cannot be
presented as additional useful confirmations.

Each observation binds the schedule's `id`, `operator`, `cohort` and
`operation_sha256`, plus `outcome`, `started_unix_ms`, `terminal_unix_ms`,
`elapsed_ms`, `cpu_ns`, `peak_rss_bytes`, `rx_bytes`, `tx_bytes` and
`raw_receipt_sha256`. Elapsed time must equal **terminal minus scheduled**
time, so client queueing or delayed submission cannot reset the service
clock. A confirmed outcome also supplies `block_id`, `confirmed_depth`
and `observed_chainwork_delta`. Original authenticated receipts must
separately establish those claims and any later reorg/loss.

The reader keeps `timeout`, `busy`, `unavailable`, `rejected`, `cancelled`
and `send_failed` outcomes. Missing records remain failures in the original
scheduled denominator. Duplicate operations, duplicate observations, unknown
IDs, context swaps, negative/nonfinite costs and duplicate JSON keys reject.
Every operator/cohort must meet its own frozen floor; a successful aggregate
cannot hide a failed operator. Resource totals include recorded failures;
missing records also mean incomplete resource accounting. Success-only
latency quantiles are labeled as such and never replace all-operation
deadline completion.

```sh
python3 scripts/pon_wan_evidence.py frozen-manifest.json original-observations.jsonl
python3 -m unittest discover -s scripts/ci -p test_pon_wan_evidence.py -v
```

The nine synthetic negative/control tests are reader tests, not WAN
observations. Exit 0 means the supplied rows meet the arithmetic thresholds;
it does not authenticate administrative independence, signatures, source
identity, physical duration, state safety, model quality or repair duties.
Those flags remain false even when arithmetic succeeds. An independent
acceptance review must join the verified originals and every separate safety,
Cell/Hepta, fault, resource and service cohort before considering PN5.

## Current execution boundary

The current workspace supplies neither three independent operators nor their
authorized WAN deployment/monitoring environments. It has not run 72 hours
and cannot acquire that evidence by accelerating a clock, replaying rows or
renaming local processes. Work package 5 is **NOT RUN / HOLD_NO_GO**. The
reader makes missing evidence visible; it does not supply it.
