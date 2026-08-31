# TRNM Agent Work Package Template v1

Status: **template; copy into a package-specific subordinate contract**

## 1. Authority

```text
package_id =
gate_id =
agent_id =
repository = TrillionniumFoundation/Trillionnium-Chain
base_ref =
base_commit =
base_tree =
plan_id = trnm-ai-native-blockchain-development-plan-v1
plan_sha256 =
machine_truth_sha256 =
protocol_manifest_sha256 =
classification = candidate-non-normative
```

State explicitly whether branch tip, code source, tested source and assessed
source differ.

## 2. Objective

One capability slice only. Describe the exact state or authority gap being
closed.

## 3. Explicit non-claims

List every adjacent Gate/capability that remains false. Always include release,
production, activation and any downstream Gate not accepted.

## 4. Ownership

### Owned paths/surfaces

```text
...
```

### Forbidden paths/surfaces

```text
...
```

### Sole capabilities owned

| Capability/interface | Issuer | Consumer | Serialization | Replay rule |
|---|---|---|---|---|

## 5. Upstream immutable inputs

List exact interface/schema/domain/parameter/evidence digests. A missing or
changed input creates `BLOCKED_UPSTREAM` or `BASE_DRIFT`.

## 6. Public interface freeze

For every added/changed interface define:

- semantic version;
- canonical bytes/domain;
- caller and issuer authority;
- bounds;
- errors;
- idempotency/replay;
- durability;
- compatibility and rejection;
- downstream consumers.

## 7. State machine

```text
Source
 -> Pending
 -> DurableIntermediate
 -> Target
```

List terminal, retryable, quarantined and fail-stop states.

## 8. Invariants

### Safety

### Liveness/availability

### Durability/recovery

### Economic conservation

### Privacy/custody

## 9. Bounds

| Resource | Bound | Enforcement point | Error |
|---|---:|---|---|
| bytes | | | |
| nested items/depth | | | |
| signatures/CPU | | | |
| storage/retention | | | |
| time/retries | | | |

## 10. Positive vectors

Each vector binds exact input bytes, expected output/root/error, command and
evidence ID.

## 11. Negative mutants

Retain every mutant. At minimum consider unknown/trailing/duplicate/cross-
version/overflow/replay/stale/fork/root/authority/path/rollback substitutions.

## 12. Fault/crash/replay matrix

| Cut | Residue | Restart owner | Exact allowed outcome | Forbidden outcome |
|---|---|---|---|---|

Classify process kill, kernel/host reboot, power loss and coherent namespace
rollback separately.

## 13. Exact commands and artifacts

```text
build =
test =
clippy =
format =
fuzz/formal =
process/network =
replay =
```

Record toolchain, binaries, SBOM, topology, workload, fault schedule and raw
trace roots.

## 14. Gap ledger

| Gap ID | Severity | Status | Dependency | Evidence | Next action |
|---|---|---|---|---|---|

Status is one of `open`, `working`, `blocked-upstream`, `closed-candidate`,
`invalidated`, `reopened`.

## 15. Evidence envelope

Use the engineering evidence contract and `agent-handoff-v1`. Always state
scope, authority and classification.

## 16. Module-local exit criteria

Define machine-checkable assertions for `MODULE_CLOSED_CANDIDATE`. Do not use
this section to promote a Gate.

## 17. Rollback and operator recovery

Explain branch rollback, data compatibility, durable state recovery and any
required quarantine/manual decision.

## 18. Downstream invalidation

List every package/vector/client/benchmark/release record invalidated by source,
interface, schema, parameter or evidence changes.

## 19. Independent review

```text
reviewer =
second_replay_owner =
required_review_domains =
```

The package owner cannot independently accept or merge its own package.
