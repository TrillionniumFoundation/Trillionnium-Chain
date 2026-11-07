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

The original nine v1 synthetic negative/control tests are reader tests, not WAN
observations. Exit 0 means the supplied rows meet the arithmetic thresholds;
it does not authenticate administrative independence, signatures, source
identity, physical duration, state safety, model quality or repair duties.
Those flags remain false even when arithmetic succeeds. An independent
acceptance review must join the verified originals and every separate safety,
Cell/Hepta, fault, resource and service cohort before considering PN5.

## Explicit typed and windowed v2

The same reader additionally accepts `trnm-wan-preregistration-v2` and returns
`trnm-wan-evidence-accounting-v2`. V1 retains its original confirmation-only
interpretation. A v2 Cell retrieval, repair or recovery must satisfy its own
frozen result type; a `confirmed` transaction cannot stand in for these effects.
No additional campaign runner, deployment authority or default SLO is introduced.

V2 objects reject unknown or missing fields. All thresholds below must be
explicitly preregistered. The reader checks the claimed registration timestamp
precedes the declared start; it does not authenticate when registration happened.

### Frozen manifest

The top-level fields are:

| Field | Required meaning |
|---|---|
| `schema` | `trnm-wan-preregistration-v2` |
| `preregistered_unix_ms` | Claimed registration time, strictly before start |
| `start_unix_ms`, `end_unix_ms` | Declared campaign interval of at least 72 hours |
| `chain_source_sha256`, `hepta_source_sha256` | Exact source identity references |
| `chain_binary_sha256`, `hepta_binary_sha256` | Exact binary identity references |
| `threat_model_sha256`, `load_fault_plan_sha256` | Frozen threat, offered-load, attack/fault and stopping-plan references |
| `operators` | The five v1 operator fields; at least three distinct operator, administrator and failure-domain declarations |
| `windows` | Ordered objects with `id`, `start_unix_ms`, `end_unix_ms`, `report_by_unix_ms` |
| `cohorts` | Explicit typed policies described below |
| `schedule` | Every original operation, its window and its expected result identities |

Windows must form a contiguous, nonoverlapping partition of the whole campaign.
Each reporting cutoff is explicitly frozen and cannot precede its window's end.
The reader materializes every **operator × cohort × window** group, including
groups with no scheduled or recorded rows. Such groups cannot disappear into
an aggregate. A schedule's completion deadline must fit wholly within its window.

For each operator/cohort pair, the first-to-last scheduled-operation span must
also be at least 72 hours. Merely writing a 72-hour start/end interval while
placing all observations in the first seconds fails. The end must leave enough
time for the last operation's original completion deadline; this can require an
interval longer than exactly 72 hours. These are timestamp-accounting checks,
not proof of physical operation or continuous availability between samples.

Every cohort has exactly these fields:

| Field | Interpretation |
|---|---|
| `id`, `kind` | Named cohort and one of `confirmation`, `cell_retrieval`, `replica_repair`, `recovery` |
| `max_completion_ms` | Maximum scheduled-to-terminal time for timely success |
| `minimum_samples_per_operator_per_window` | Frozen planned denominator floor for each group |
| `minimum_timely_ppm` | Required timely successes per million scheduled operations |
| `tail_quantile_ppm` | Explicit success-only nearest-rank quantile, from 1 through 1,000,000 |
| `minimum_tail_samples_per_operator_per_window` | Separate minimum number of eligible successful tail samples |
| `max_tail_latency_ms` | Required bound on the selected quantile |
| `window_resource_limits` | Explicit per-group limits for `cpu_ns`, `peak_rss_bytes`, `rx_bytes`, `tx_bytes`, `funding_units` |
| `success_criteria` | Exact type-specific policy below |

Resources sum all recorded attempts, including failure and late rows; peak RSS
uses the maximum. A zero limit must be explicitly supplied. Missing observations
leave incomplete accounting, even if the sum of reported costs is below its
limit. `funding_units` is a reported cost, not payment evidence or budget authority.
A declared tail sample floor is not itself a proof of statistical sufficiency.
The small thresholds in reader tests are synthetic test inputs, not suggested
WAN, latency, repair or economic objectives.

### Typed schedule and observations

Each schedule row has `id`, `operator`, `cohort`, `window`,
`operation_sha256`, `scheduled_unix_ms`, and `expected`. An original operation
hash is unique across the complete schedule. `expected` freezes the following
object identities and amounts before the campaign:

| Kind | `success_criteria` | `expected` |
|---|---|---|
| `confirmation` | `minimum_confirmed_depth`, `minimum_chainwork_delta`, both positive | Empty object |
| `cell_retrieval` | Positive `minimum_source_operators` | `manifest_sha256`, `payload_sha256`, positive `payload_bytes`, `forbidden_source_operators` |
| `replica_repair` | `minimum_complete_replicas`, `minimum_administrators`, `minimum_failure_domains`, each at least 3 | `manifest_sha256`, `payload_sha256`, positive `payload_bytes`, `effect_sha256` |
| `recovery` | `mode`, `maximum_redispatched_effects`, `maximum_new_payments`; both maxima must be explicitly zero | Mode-specific fields below |

Recovery `mode` is one of:

- `reconcile`: expected `effect_sha256` and `target_receipt_sha256`;
- `verified_sync`: expected `tip_sha256` and `state_root_sha256`;
- `restart`: expected `state_root_sha256` and `frontier_sha256`.

Each v2 observation has exactly `id`, `operator`, `cohort`, `window`,
`operation_sha256`, `outcome`, `started_unix_ms`, `terminal_unix_ms`,
`recorded_unix_ms`, `elapsed_ms`, `resources`, `raw_receipt_sha256`, `result`.
The five `resources` fields have the same names as the frozen limits. Integer
quantities are unsigned 64-bit values; booleans, negative and nonfinite values
cannot become costs. IDs/context must match the schedule. The clock remains
**terminal minus originally scheduled time**; delayed sending cannot renew it.
Recording cannot precede the terminal event.

Successful `result` objects are:

| Outcome | Exact fields and arithmetic criteria |
|---|---|
| `confirmed` | `block_id`, `confirmed_depth`, `observed_chainwork_delta`; compare depth/work to the frozen criteria |
| `retrieved` | `manifest_sha256`, `payload_sha256`, `payload_bytes`, `source_operators`; exact target, sufficient distinct declared sources and no forbidden origin |
| `repaired` | `manifest_sha256`, `payload_sha256`, `payload_bytes`, `effect_sha256`, `complete_replica_operators`; exact target/effect and enough complete-copy declarations across the frozen administrator/domain identities |
| `recovered` | The expected mode-specific hashes plus `mode`, `redispatched_effects`, `new_payments`; exact state/effect and zero redispatch/new payment |

Source/replica operator lists cannot contain duplicate or unknown identities.
Each raw receipt reference must be unique across v2 observations. A bundled
external log must supply distinct operation-bound receipt references; repeatedly
attaching the same receipt is not another sample. Receipt hashes and replica
lists remain claims awaiting independent authentication and physical readback.

Failure outcomes retain the v1 names and use an empty `result` object. A claimed
successful outcome with validly shaped but mismatching hashes, bytes, depth,
replica count or recovery facts is counted as a `success_criteria_failure` in
its original denominator. A success type belonging to another cohort rejects.

### Window, tail and release boundaries

Missing observations, records after the frozen reporting cutoff, and terminal
events after their original window make that group's accounting incomplete.
Their reported costs remain counted. They cannot supply eligible successful
tail samples. A success inside its window but after its completion deadline
remains in success-only latency statistics and fails the timely-success test.
The exact integer nearest-rank quantile and its separate sample floor must both
pass. Meeting the ratio with too few eligible tail samples remains unaccepted.

The overall arithmetic result is the conjunction of every named group's
coverage, denominator, tail, resource and timely-completion checks. There is no
aggregate override. The same CLI and test command shown above handle both
versions; sixteen additional v2 controls include real CLI execution, early-only
sampling, empty groups, late arrivals, replayed receipts, wrong result types,
wrong Cells, forbidden origins, collapsed replica domains and repeated effects.

Even exit 0 leaves `external_operator_attestations_verified`,
`physical_wan_duration_verified`, `raw_receipts_cryptographically_verified`,
`preregistration_independently_verified`, `source_binary_identities_verified`,
`independent_accepted`, `pn5_accepted`, `public_network_ready` and
`production_activation` **false**. Local JSON arithmetic cannot supply PN5
acceptance, physical replication, quantum-safe authentication or governed
activation. The current NOT RUN boundary below remains unchanged.

## Current execution boundary

The current workspace supplies neither three independent operators nor their
authorized WAN deployment/monitoring environments. It has not run 72 hours
and cannot acquire that evidence by accelerating a clock, replaying rows or
renaming local processes. Work package 5 is **NOT RUN / HOLD_NO_GO**. The
reader makes missing evidence visible; it does not supply it.
