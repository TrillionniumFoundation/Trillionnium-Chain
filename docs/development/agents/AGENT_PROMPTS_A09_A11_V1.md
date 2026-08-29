# TRNM Agent Prompts A09-A11 v1

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

## A09 — Independent Parser, Vectors, Mutation and Fuzz

```text
Start and own package G15_INDEPENDENT_CONFORMANCE_V1 for Gate G1.5.
Mission: Build a genuinely independent strict parser/verifier and signed positive/negative/differential/mutation/fuzz corpus.
Upstream dependencies: A08.
Owned surfaces: independent parser implementation outside canonical crates; conformance/cev1/**; fuzz/cev1/**; conformance evidence.
Forbidden surfaces: linking/importing the canonical parser/serializer; editing canonical protocol implementation; calling itself independent if it shares parsing/signature code.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: strict independent decoding/re-encoding; digest/signature/root reproduction; duplicate/trailing/unknown/cross-version/bounds negatives; mutant retention; clean-clone independent replay.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Independent and canonical implementations agree on every accepted byte/root/error.; All malformed and cross-version cases fail with expected classes.; The independent implementation shares no parser or verification code..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A10 — G2.0 W0-W7 Traceability and Codegen

```text
Start and own package G20_W0_W7_TRACEABILITY_V1 for Gate G2.0.
Mission: Generate complete operation-kind and vertical trace rows from CEV1 admission through DA, Order, execution, result, settlement and external proof surfaces.
Upstream dependencies: A08, A09.
Owned surfaces: W0-W7 traceability registry; 30 operation row generator; logical wire and authenticated transport contracts; RPC/WS/SDK/indexer schema projection.
Forbidden surfaces: local kernel semantic changes; production RPC deployment; marking a row complete at a local SQLite/composite root.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: 30 generated rows; AgentTransactionV1 admission binding; BatchRef/DA binding; Order/receipt/JMT binding; Result/Settlement binding; RPC/SDK/indexer/light-client projection.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Every enabled operation traverses every applicable W0-W7 link.; Disabled operations terminate in a canonical rejection vector.; Two independent parser results and evidence IDs are attached..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A11 — G2A DA-FULLREP-V1

```text
Start and own package G2A_DA_FULLREP_V1 for Gate G2A.
Mission: Close the full-replication transaction/artifact DA candidate: durable-before-attest, authenticated retrieval, repair, withholding, retention and BatchRef interface.
Upstream dependencies: A08, A10.
Owned surfaces: trillionnium/crates/trnm-poco-da-v1/**; DA protocol/contracts/vectors; DA focused gates and conformance.
Forbidden surfaces: Order vote authority; production GC permit issuance; DA-DAS activation or sampling claims.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: ArtifactEvidence namespace; author and responder signer journals; authenticated P2P request/response; generic ranges and quotas; withholding/non-response adjudication; Node-owned GC authority interface; proposal retrieval-before-vote binding.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: No certificate exists without promised durable bytes.; Namespace, range, root, stale certificate and incomplete repair mutants fail closed.; DA-DAS remains explicitly disabled..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```
