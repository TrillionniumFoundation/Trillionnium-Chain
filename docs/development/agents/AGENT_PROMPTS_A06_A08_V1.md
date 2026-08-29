# TRNM Agent Prompts A06-A08 v1

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

## A06 — G1-R4 Fault Matrix and Independent Replay

```text
Start and own package G1_R4_FAULT_MATRIX_V1 for Gate G1.
Mission: Independently prove every durability edge under SIGKILL, response loss, disk full, I/O failure, torn write, rollback, skew and multi-block/fork conditions.
Upstream dependencies: A02, A03, A04, A05.
Owned surfaces: trillionnium/crates/trnm-poco-node/tests/**; trillionnium/crates/trnm-poco-lab-validator/**; scripts/ci/**/*process_matrix*; scripts/faults/**; docs/evidence/g1-r4/**; R4 crash/fault matrix documents.
Forbidden surfaces: production semantics; production capability constructors; editing module-owned source except approved test-only injection hooks.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: full application/Safety/checkpoint cut matrix; disk-full and torn-write coverage; independent process-2 implementation; multi-block/fork/anti-rollback campaigns; raw evidence bundle generation; power-loss evidence classification.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Every named durable edge has positive, negative and restart cases.; The harness cannot mint production authority.; Independent replay agrees on bytes, roots, status and error classes.; Failures and mutants remain retained and indexed..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A07 — G1-R5 Native 4/7-Node Campaign

```text
Start and own package G1_R5_NATIVE_NETWORK_CAMPAIGN_V1 for Gate G1.
Mission: Prove the accepted single-node G1 authority on real 4/7-node process and multi-host campaigns.
Upstream dependencies: A06.
Owned surfaces: network campaign scripts/configs; validator topology and identity manifests; multi-host evidence collection; docs/development/packages/**/*R5*; campaign workflows.
Forbidden surfaces: changing consensus safety semantics; production key material; promoting transport smoke as validator-run evidence.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: normal finality; minority offline/rejoin; leader crash/TC; 3-1 progress and 2-2 stall/heal; restart/catch-up/state sync; epoch/key rotation; signer/disk faults.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Zero conflicting finality, double-sign or state-root divergence.; Process/host/operator/region counts are reported separately.; Campaign evidence binds exact binary, genesis, workload and fault schedule..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A08 — G1.5 CEV1 Registry and Normative Specification

```text
Start and own package G15_CEV1_REGISTRY_SPEC_V1 for Gate G1.5.
Mission: Complete the normative object/domain/error/operation/limits/profile inventory, threat model, status taxonomy and UP-V0-V1 specification.
Upstream dependencies: A00, A01.
Owned surfaces: docs/protocol/poco-ai-native-v1/**; docs/schemas/poco-ai-native-v1/**; CEV1 registries and code generators; spec consistency gates.
Forbidden surfaces: status promotion fields; G1 production implementation; claiming normative freeze before accepted review and G1 exit.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: complete object catalog; 30 operation assignments; domain/error/limit registries; version negotiation and cross-version rejection; verification profile registry; upgrade/no-downgrade contract; independent-domain review package.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Every enabled object has one schema, domain, bound and owner.; Unassigned operations are explicitly disabled.; No Critical/High specification ambiguity remains.; Normative-freeze remains blocked until its prerequisites are accepted..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```
