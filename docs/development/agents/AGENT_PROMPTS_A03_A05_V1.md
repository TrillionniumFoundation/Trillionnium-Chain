# TRNM Agent Prompts A03-A05 v1

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

## A03 — G1-R3 Ordinary Proposal Authority

```text
Start and own package G1_R3_ORDINARY_PROPOSAL_AUTHORITY_V1 for Gate G1.
Mission: Generalize the bounded synced-proposal fixture into a real ordinary non-empty proposal path ending in a same-owner AuthorityVote.
Upstream dependencies: A02.
Owned surfaces: ordinary proposal validation and authority modules; trillionnium/crates/trnm-native-execution-v0/**; proposal-side effect-driver integration; docs/development/packages/**/*R3*; ordinary-proposal focused tests and gates.
Forbidden surfaces: finalization queue/application apply owned by A04; SafetyStore/signer/checkpoint owned by A05; direct broad rewrites of core.rs without an approved thin module hook.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: complete body and evidence retrieval; parent/JMT/validator/parameter/runtime-profile binding; deterministic Valid/Unavailable/DeterministicallyInvalid mapping; safe-vote owner affinity; remote signer intent with no raw key in node; process restart and mutation corpus.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: A real non-empty ordinary proposal reaches a signed Vote in a process test.; Every root, context, version and authority mutation fails closed.; Unavailable is never silently mapped to invalid or valid.; No finality or application commit authority is fabricated..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A04 — G1-R4 Application and Ordered Finality

```text
Start and own package G1_R4_APPLICATION_FINALITY_V1 for Gate G1.
Mission: Close contiguous ancestor-ordered finalization, exact application apply/JMT promotion, committed readback, idempotent retry and fork reclamation.
Upstream dependencies: A03.
Owned surfaces: trillionnium/crates/trnm-native-application/**; trillionnium/crates/trnm-native-application-sqlite/**; finalization queue and application-finalization modules; docs/development/packages/**/*R4B*; application-finalization focused tests and gates.
Forbidden surfaces: SafetyStore/signer/checkpoint owned by A05; fault-harness ownership owned by A06 except approved test hooks; ordinary proposal validation owned by A03.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: complete finalization queue lineage; application intent-to-commit process boundary; ascending multi-block apply; atomic queue acknowledgement and committed-head readback; duplicate apply rejection; losing-fork retention/reclamation; response-loss recovery.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Zero lost or skipped ancestor.; Zero duplicate apply or post-state-root drift.; Response loss resolves to exact source or target.; Fork reclamation never deletes still-referenced evidence..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A05 — G1-R4 Safety, Signer, Checkpoint and Anti-Rollback

```text
Start and own package G1_R4_SAFETY_CHECKPOINT_V1 for Gate G1.
Mission: Close tag-3 Safety durability, signer journal/watermark ordering, whole-node checkpoint CAS and coherent anti-rollback before any signature escapes.
Upstream dependencies: A03, A04.
Owned surfaces: trillionnium/crates/trnm-consensus-safety-rules/**; trillionnium/crates/trnm-consensus-safety-store/**; trillionnium/crates/trnm-consensus-signer-journal/**; trillionnium/crates/trnm-consensus-external-watermark/**; trillionnium/crates/trnm-consensus-external-node-checkpoint/**; trillionnium/crates/trnm-whole-node-checkpoint-types/**; remote signer protocol/service modules; docs/development/packages/**/*R4C*.
Forbidden surfaces: application object mutation/JMT final apply owned by A04; ordinary proposal execution owned by A03; network campaign harness owned by A07.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: real production-composition Safety owner; tag-3 persist/readback; Application/Safety/Signer cross-store checkpoint CAS; external monotonic anti-rollback anchor; coherent namespace rollback; signer/Safety/Application skew; HSM/KMS-facing custody contract.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: No signature escapes before exact durable Safety and checkpoint evidence.; Mixed or stale cuts fail before sign/vote/apply.; Coherent rollback is detected before authority use.; No raw private key enters the default node..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```
