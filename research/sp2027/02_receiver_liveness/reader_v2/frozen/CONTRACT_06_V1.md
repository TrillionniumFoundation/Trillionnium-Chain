# SP27-02/06 business-confirmation event contract, version 1

Status: implemented interface proposed for coordination. This document and the
analyzer define measurement semantics, not a new consensus protocol or permission
to weaken a native check. A joint freeze requires the 02 execution owner and the
coordinator to accept the same contract, schedule digest, and observation pipeline.
Merely writing this file is not evidence of that acceptance.

## 1. Scope and authority

`analyzer.py` uses only Python's standard library. It consumes one JSON contract,
one JSONL planned schedule, and one JSONL event stream. It checks types, identities,
ordering, explicit confirmation predicates, and accounting scopes. It does not
execute W1, verify signatures, establish observer independence, authenticate logs,
or prove finality. A positive observation must come from the pinned native
independent verification path; its provenance and the correctness of that path
remain explicit evidence assumptions. A hash binds bytes, not their truth.

Separate `native_experiment`, `archival_reanalysis`, and `synthetic_validation`.
Synthetic tests never become native benchmark data. The analyzer itself executes
zero native experiments. Historical archives retain their own implementation and
binary identities; a new evidence commit or current branch must not replace them.

## 2. Files, identities, and freeze

Before a new experiment, freeze and hash:

1. `contract.json`: security policy, endpoints, windows, source/build/configuration,
   host and resource arrangement, workload interpretation and experimental units.
2. `schedule.jsonl`: every planned business operation and its intended arrival.
3. The collector version and its expected event and resource-owner coverage.

Record separate implementation commit/tree, compiler and lockfile, binary digest,
configuration digest, running host/boot/process identity, resource limits,
affinity, concurrent jobs, source/data/model/task identities, K/H/receiver/task
size axes, trial ordering/seed, setup/warmup/drain, and clock resolution/error in
the run's `identity` and `metadata`. Unknown observations remain null. Native
experiments require all four principal identities; archived records may have
missing identities and expose them in `identity_missing`. A hash of an observed
configuration subset is a `metadata.observed_config_view_sha256`, not a complete
configuration hash.

`plan_provenance` distinguishes a schedule actually frozen before execution from
one reconstructed from a fixed original fixture. Retrospective reconstruction
must not be called preregistration. Record old eligibility gates without modifying
them. The original four-second traffic epoch and thirty-second campaign are
separate profiles. No result gets a fresh deadline after a delayed actual start.

The machine schemas are `contract.schema.json`, `schedule.schema.json`, and
`events.schema.json`. They describe structure. Cross-file bindings, exact integer
checks, alias rules, and endpoint semantics are enforced by the analyzer.

## 3. Contract format

The top-level object has `schema="sp27-confirmed-goodput-contract-v1"`,
`evidence_scope`, and `runs`. Each run has:

| Field | Meaning |
|---|---|
| `run_id` | Unique analysis stratum/trial/phase identity. |
| `chain_instance_id` | Execution state namespace, including reset identity. |
| `profile_id` | Fixed workload/security/measurement profile. |
| `clock_id` | Monotonic domain used for the primary endpoint. Include boot identity. |
| `observer_id` | Native independent confirming actor, not the receiver's ACK actor. |
| `window_start_ns`, `window_end_ns` | Fixed observation interval; end must exceed start. |
| `identity` | `source_commit`, `source_tree`, `binary_sha256`, `config_sha256`. |
| `confirmation_policy` | Frozen policy object described below. |
| `event_coverage_complete` | Whether absence of a start event proves it did not start. Default false. |
| `expected_resource_owners` | Optional complete inventory of disjoint resource owners. |
| `resource_inventory_complete` | False unless the owner inventory was established. |
| `recovery` | Optional sustained recovery rule fixed before observation. |
| `metadata` | Host/build/axes/provenance/error/coverage details; preserved in output. |

`confirmation_policy` contains `policy_id`, integer `min_depth`, hexadecimal
`required_work_delta`, `semantics`, and `window_end_rule` (`inclusive` or
`exclusive`). New native experiments must declare the boundary rule. The default
inclusive rule exists only for legacy/synthetic input compatibility; the imported
original Chain native predicates use **exclusive** (`< end`). The required-work threshold may instead be
pinned on each schedule row; it must not be taken only from the received event.

- `first_observed`: first qualifying native observation is the finite endpoint.
  Later invalidations are retained but do not rewrite the historical milestone.
- `valid_at_window_end`: observations invalidated by the cutoff cannot count.
  This additionally requires `invalidation_coverage_complete=true`; missing
  invalidation timing/clock mappings prevent the affected observation from counting.

These are different claims. Neither is an unconditional consensus-finality claim.

## 4. Scheduled business operations and identity

Each schedule row contains `operation_id`, `run_id`, nullable integer
`scheduled_ns`, nullable integer `deadline_ns`, nonempty `transaction_ids`,
nullable `content_id`, nullable `useful_compute_id`, nullable
`useful_compute_evidence`, and nonempty `plan_provenance`.
Optional `expected_block_id` binds the included block; optional
`required_work_delta` pins a per-operation work threshold.

`scheduled_ns=null` is allowed for archival material lacking a prospective arrival
timestamp. It does not become actual start or zero. The corresponding scheduled
latency remains missing. New native experiments require a planned timestamp.
`deadline_ns` is an optional per-operation SLO, separate from the run's window.
A deadline beyond the observed window is unresolved without a timely observed
success; it is not automatically a failed SLO.

Count each operation once across retries, transaction replacements, multiple
confirming responses and multiple receivers. Operation IDs must be unique in the
schedule. A transaction identity cannot be assigned to two operations in the same
`chain_instance_id`; this would double-credit a single ledger transaction. A
repeated transaction across independently reset instances can represent separate
execution trials. Do not globally deduplicate those trials into one experiment.

The counted quantities answer different questions:

- **Business operations:** distinct planned logical effects/trials.
- **Transactions:** distinct confirmed ledger identities within a chain instance.
- **Content:** distinct objects under the explicitly chosen canonicalization.
- **New useful computation:** distinct independently justified useful-computation
  identities, with the relevant context, freshness and usefulness evidence.

Equality or inequality of operation IDs does not establish the other three.
Unknown content or useful-computation identity gives partial coverage and a null
complete count. A nonempty useful-computation evidence reference is a traceability
requirement, not proof that the scientific usefulness predicate was met.

## 5. Events and confirmation endpoint

Every event contains `event_id`, `run_id`, `operation_id` (nullable for lifecycle
events), `type`, nullable integer `at_ns`, `clock_id`, `actor_id`, and nullable
`attempt_id`. Timestamps are integer nanoseconds; booleans, floating point clocks,
negative integers and nonfinite numbers are refused. No unrelated monotonic
clock domains are subtracted. An adapter must supply a verified mapping before
placing a timestamp in the primary domain; record its uncertainty in metadata.
Unmapped confirmations remain rejected observations. This version does not
convert uncertain cross-host clock intervals into exact timestamps.

Types are `request_start`, `confirmation`, `invalidate`, `failure`, `cancelled`,
`unknown`, `not_started`, `ack`, `head`, `admitted`, `seed`, `stage`, `attempt_end`,
`attack_start`, `attack_stop`, `observer_end`, and `resource`.

`ack`, `head`, `admitted`, component stages and seed data are telemetry. They
cannot become business confirmations. A confirmation additionally carries:

- Bound `transaction_id`, `block_id`, `policy_id`.
- Integer `depth`; hexadecimal `work_delta` and `required_work_delta`.
- `execution_authority=false`, preserving the native observation's authority scope.
- `flags`: booleans `full_verification`, `admission`, `host`, `history`,
  `activation`, all true for a qualifying observation.
- `provenance`: a 64-hex `artifact_sha256`, `member`, and JSON `pointer`.

When the policy sets `require_native_window_gate=true`, include boolean
`native_window_gate` copied from the original native deadline predicate. The
original fixtures check a fresh clock **after** recording the confirmation end;
their native gate therefore cannot always be reconstructed from the earlier
timestamp alone. A missing/false gate receives no timely credit. Its observed
confirmation timestamp and any late delay are still retained with a rejected
gate diagnostic. This distinction does not change the old archive counts: none
of their observed qualifying endpoints sits exactly on the cutoff.

Flags are attestations from the retained native endpoint and pinned implementation,
not fresh cryptographic checks by this Python program. An archival adapter must
describe the source evidence that justifies them; missing or false flags do not
count. They must never be synthesized from ACK, accepted-work or Head status.
The actor, transaction, optional expected block, policy, depth and required-work
threshold must bind. Confirmation cannot precede planned or known actual start.

Missing/false endpoint evidence yields a retained rejected-confirmation record,
not a successful observation. Structurally malformed or contradictory evidence
causes `ANALYSIS_REFUSED` without emitting a usable result. Repeated identical
event IDs are deduplicated; conflicting reuse of an event ID is refused.

An `invalidate` event names `target_event_id` and must bind the same run and
operation. An explicit `not_started` event in the run's declared primary clock
domain can establish an unstarted scheduled operation. A simultaneous known
`request_start` contradicts it and is refused. An unmapped `not_started` claim
does not establish an unstarted outcome. Otherwise an absent event stream is `unknown` unless complete start
coverage is declared. Terminal cancellation or failure is retained even if a real
confirmation is subsequently observed; a cancellation request does not undo an
already committed effect.

## 6. Metrics, clocks, and censoring

For a fixed run, let B be all scheduled operation rows and let N be the number
with a valid confirmation satisfying the frozen window boundary and required
native gate. The start and end timestamps, exact numerator and denominator are
retained in output.

`window_success_fraction = N / |B|`

`confirmed_goodput = N * 1e9 / (window_end_ns - window_start_ns)`

This is finite fixed-workload goodput. It is not a saturated capacity estimate.
Capacity requires offered-load scans under unchanged security policy and complete
cost/success accounting. K is complete state population; H is complete relevant
history. A bounded batch alone does not remove global K/H dependence.

The endpoint comparison follows the frozen `window_end_rule`. Imported Chain
native profiles use strict `confirmation < window_end` and preserve their native
window predicate. The per-operation deadline SLO uses an inclusive deadline
comparison (`confirmation <= deadline_ns`) in addition to the run's window rule.
Both metrics
keep failed, unstarted, cancelled, Unknown, and unconfirmed planned operations in
their denominators. If an SLO is not observable or not declared for every
operation, its complete planned-denominator fraction is null.

Scheduled latency is confirmation minus planned arrival. Actual-start latency
and start lateness are separate columns. Missing latency is null (blank in CSV),
never zero. Successful conditional quantiles use the nearest-rank convention;
each quantile block also reports all planned operations, successful count,
missing successful latencies, and nonconfirmation count/rate. The planned
denominator CDF divides by all operations, so it need not reach one. It cannot
represent unobserved scheduled latencies as known.

Outcomes remain `confirmed`, `late_confirmed`, `failed`, `cancelled`, `unknown`,
`unstarted`, or `unconfirmed`. Administrative censoring at the window is distinct
from terminal failures and uncertain evidence. A failure first observed after
the deadline does not rewrite the original window's unresolved status. Late
confirmations are retained with their observed delay but receive no original
window credit. No Kaplan–Meier eventual-latency estimate is produced: independent
censoring cannot be assumed for these service failures.

Results are emitted per run without pooled confidence intervals. Multiple
phases, packets, workers, or repeated transactions are not automatically
independent experimental units. Heterogeneous original binaries remain separate.

## 7. Complete resource lifecycle and recovery

A resource event additionally specifies integer `value`, `metric`, `owner_id`,
`scope`, `inclusive`, `coverage`, and nullable paired `started_ns`/`ended_ns`.
Metrics are CPU nanoseconds, read/write/network RX/TX bytes, energy microjoules,
peak RSS bytes and storage bytes. Scopes are setup, warmup, window, drain,
recovery and whole lifecycle. All attempts, failures and terminal work should
be measured under the relevant owners.

Inclusive nested spans are retained under `resources.inclusive_observations`,
including their values, owners, scopes, coverage, native-field/provenance pointers
and exclusion reason, but excluded from sums. They remain visible even when no
disjoint owner total can be constructed. Overlapping
exclusive additive spans for one owner/metric/clock are refused. Unknown or
cross-clock intervals prevent ambiguous multi-span totals. Without a complete
owner inventory and complete records, report observed scoped totals and leave
complete totals null. A missing metric is missing, not a measured zero. A list of
measured metrics cannot establish that every possible cost was measured, so
`all_costs_measured` is conservatively false.

Resource elapsed spans are half-open `[started_ns, ended_ns)`, so a span ending
exactly at the cutoff can be fully in-window regardless of the instantaneous
confirmation boundary rule. Whole-call CPU crossing the window remains a whole-call observation. Wall-time
fractions do not identify in-window CPU and are never used to prorate it. Memory
peaks at different times or owners are not added into a fictitious simultaneous
service peak. Cost per successful operation is null when no operation succeeds;
the positive incurred total remains visible.

An optional recovery rule contains `attack_stop_ns`, `bin_ns`,
`consecutive_bins`, `min_planned_per_bin`, `min_success_fraction`, and
`latency_slo_ns`. It evaluates full-width bins after pressure stops that end
within the declared observation window, counting scheduled operations and their
valid confirmations by each bin end. Recovery
requires the successful endpoint and its native window gate; a retained timestamp
from a rejected gate cannot count. A lucky
single operation is insufficient unless that was the explicitly frozen criterion.
Reported `recovery_time_ns` is time until the required consecutive bins complete;
the beginning of the sustained interval is separately reported. If not observed,
the criterion is `right_censored`, meaning not certified before cutoff, without
inferring complete observer coverage or independent statistical censoring.
Observation loss/Unknown remains in the operation ledger; there is no separate
unknown recovery-state estimate. If no criterion was declared, it is
`not_measured` with a null duration. The analyzer does not infer a recovery rule
after seeing data.

## 8. Reproduction and tests

```sh
python3 analyzer.py --contract contract.json --schedule schedule.jsonl --events events.jsonl --out-dir results
python3 -m unittest -v test_analyzer.py
```

Outputs are `summary.json`, `operations.csv`, and
`validated_input_manifest.json`. The latter pins exact input bytes and analyzer
source. `load(path)` and `analyze(path)` accept a directory containing the three
conventional filenames; `analyze(contract, schedule_rows, event_rows)` accepts
in-memory input. Outputs are deterministic for the same bytes and program.

Tests use only synthetic fixtures and mutation cases. They cover denominator
attrition, telemetry substitution, replay/alias manipulation, content/compute
distinctions, boundary clocks, missing planned arrival, cancellation/Unknown,
policy/observer/identity substitutions, reorganization, incomplete/nested/cross-
window costs, sustained recovery, invalid JSON and Python optimized mode.
These test counts are analyzer evidence; they are not chain security acceptance,
new native trials, or measured throughput.
