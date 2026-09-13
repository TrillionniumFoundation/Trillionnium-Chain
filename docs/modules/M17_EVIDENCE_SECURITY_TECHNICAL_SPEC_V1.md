# M17 Observability / Benchmark / Security / Evidence technical specification v1

Status: **implementation contract; evidence tooling is not self-acceptance authority**

## Authority

M17 defines metrics, traces, benchmark methodology, fault/fuzz/formal harnesses,
security scanning, evidence schemas and gate reports. It observes and tests
M00-M16. It cannot sign, order, execute, finalize, promote production or approve
its own output.

## Interfaces

`EvidenceManifestV1` binds source/base/prospective-merge identities, protocol and
module versions, dependency/toolchain/configuration digests, binary/SBOM/
provenance roots, topology, workload, faults, exact commands, start/end time,
raw artifact roots, controls, mutants, findings, invalidation conditions,
reviewers and signatures.

`MetricEnvelopeV1` binds metric schema, node/module identity, monotonic sequence,
measurement window and privacy class. `GateDecisionV1` names every applicable
lane and records non-empty terminal result, artifact digest and independent
review status. Missing, skipped, queued, cancelled, `action_required`, stale or
different-head lanes are not success.

## State machine

```text
Declared -> Executed -> ArtifactSealed -> IndependentlyReplayed
 -> Accepted | Rejected | Superseded
```

A source, dependency, compiler, feature, configuration, validator-set, key
policy, root format or workload change supersedes dependent evidence according
to its declared invalidation graph. Failed evidence remains immutable and is not
rewritten into a passing record.

## Persistence and recovery

Raw traces and manifests are content addressed and stored immutably or with an
independently auditable retention policy. Upload acknowledgements are verified
by digest readback. Partial uploads, missing chunks or signature mismatch keep
the evidence unaccepted. Derived summaries are reproducible from retained raw
artifacts.

## Resource bounds

Instrumentation has finite event size, label cardinality, buffer memory, disk
quota, sampling rate and upload bandwidth. Backpressure may drop explicitly
classified non-authoritative telemetry but never blocks or changes consensus.
Security logs required for incident and evidence windows have reserved quotas
and loss alarms.

## Security

CI controllers and workflow definitions used as trust roots are protected from
candidate modification. Candidate code executes without repository/release
credentials on ephemeral workers. Artifact publishers execute no candidate
code. Evidence ingestion rejects path traversal, archive bombs, mutable URLs,
unsigned substitutions and reviewer conflicts. Sensitive payloads, private
keys, bearer tokens and user data are redacted or excluded by schema.

## Observability and SLO

The `evidence-tooling-v1` profile measures instrumentation overhead,
artifact completeness, deterministic regeneration, false-pass/false-fail rate,
queue time separately from execution time, and independent replay success.
Chain performance reports committed, replay-verified goodput and order/result/
settlement finality p50/p95/p99, never ingress TPS alone.

## Verification and evidence

The harness itself requires retained failing mutants, artifact tamper tests,
clock and topology validation, empty-job detection, stale-head rejection and
review-conflict detection. Campaigns cover 4/7/31/100 processes across distinct
hosts/operators/custody domains, network faults, leader failures, disk pressure,
restart, state sync and migration. External audit, HSM, physical power and
wall-clock soak records must come from their actual independent authorities.

## Activation boundary

M17 may report readiness only when every required lane and external gate binds
the same release identity. A repository fixture, administrator statement,
self-review, shortened duration or simulated clock cannot close an external
gate. Critical or High findings block promotion until independently remediated
and replayed.
