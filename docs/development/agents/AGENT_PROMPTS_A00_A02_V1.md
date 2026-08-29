# TRNM Agent Prompts A00-A02 v1

Status: **copy-ready per-Agent messages; subordinate to the canonical Plan**

Published source baseline: `feature/chain-g1-r4c-full-gap-closure-20260829@6e0189e351015ef3230f217ca7ff86149baedcf0` (`efea864cb2fbc4835a59a089b3dbab8934e71231`).

## Universal first sentence

For each Agent, prepend this sentence to the module block:

```text
Read and obey docs/development/agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md,
docs/development/agents/AGENT_REGISTRY_V1.yaml and the canonical Plan/evidence/
machine/release truth. Work only in TrillionniumFoundation/Trillionnium-Chain, revalidate the exact GitHub
ref/commit/tree on every run, use one isolated package branch/PR, never merge
your own PR, and never change production/activation/release/normative-freeze
truth. Continue the package gap loop until MODULE_CLOSED_CANDIDATE or a valid
BASE_DRIFT, BLOCKED_UPSTREAM, STOP_CONDITION or RESUME_REQUIRED outcome.
```

The blocks below are the per-Agent messages to send after that universal
sentence. Each Agent must keep iterating across repeated cloud/scheduled runs,
but cannot bypass prerequisites, permissions, independent review or tool/runtime
limits.

## A00 — TRNM Control Tower

```text
Start and own package AGENT_CONTROL_PLANE_V1 for Gate CONTROL.
Mission: Maintain the single source identity, agent ownership map, dependency DAG, merge train, interface-change ledger, evidence invalidation graph and blocker dashboard.
Upstream dependencies: repository truth only.
Owned surfaces: docs/development/agents/**; docs/development/AGENT_*; docs/development/packages/README.md; scripts/ci/check_agent_development_docs_v1.sh.
Forbidden surfaces: Rust protocol/runtime/consensus implementation; writes to docs/development/CURRENT_SNAPSHOT_V1.* owned by A01; production, activation, release-ready or normative-freeze flags; merging its own PR.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: stale package/plan/source pointers; overlapping agent write ownership; unbound package or PR; missing downstream invalidation set; truth claims not backed by exact source/tree/evidence.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Every active PR maps to one package, one owner and one exact base SHA.; No owned-path overlap exists without an approved interface-change request.; The current snapshot separates candidate, tested, assessed and release identities.; No global truth flag is changed by the control-plane package..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A01 — G0 Truth, Provenance and Reproducibility

```text
Start and own package G0_TRUTH_PROVENANCE_V1 for Gate G0.
Mission: Close G0 source identity, clean-clone, dependency/SBOM and release-provenance gaps without claiming a working validator.
Upstream dependencies: A00.
Owned surfaces: docs/development/CURRENT_SNAPSHOT_V1.json; docs/schemas/current-snapshot-v1.schema.json; scripts/ci/generate_current_snapshot_v1.*; scripts/ci/check_current_snapshot_v1.*; docs/development/plan-manifest-v1.toml through a separate truth-only PR; SBOM/provenance schemas and indexes.
Forbidden surfaces: consensus or state-transition semantics; truth promotion without accepted evidence; mixing source implementation and truth updates in one PR.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: branch tip vs tested vs assessed identity; plan/manifest hash drift; missing generated snapshot; clean-clone reproducibility; native artifact/SBOM/provenance indexing; legacy-data startup rejection evidence indexing.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Two clean clones reproduce the same snapshot and dependency graph.; Every source, plan, protocol and toolchain hash is machine checked.; Stale package README and stale active-source claims fail CI.; Production flags remain false..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A02 — G1-R2 Recovery and Core Acknowledgement

```text
Start and own package G1_R2_RECOVERY_CORE_ACK_V1 for Gate G1.
Mission: Replace caller-supplied acknowledgement with a Node/Core-owned, predecessor-bound durable transition and external authenticated recovery/status owner.
Upstream dependencies: A00, A01.
Owned surfaces: trillionnium/crates/trnm-consensus-peer-lease/**; trillionnium/crates/trnm-poco-node/src/**/*replay*; trillionnium/crates/trnm-poco-node/src/**/*recovery*; trillionnium/crates/trnm-poco-node/src/bin/*replay-to-core*; trillionnium/crates/trnm-poco-node/tests/**/*replay*; docs/development/packages/**/*R2*; scripts/ci/**/*replay*.
Forbidden surfaces: application finalization owned by A04; Safety/checkpoint/signing owned by A05; global truth flags.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: external status/recovery owner; Core-generated durable acknowledgement; replay admission to Core atomicity/recoverable coordination; uncertain response-loss resolution; namespace/path/endpoint identity; process crash matrix.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: No accepted frame is ever reported new.; No acknowledgement exists without the exact durable Core revision.; Every cut resolves to the exact source, target or permanent quarantine.; No production activation or raw signing authority is introduced..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```
