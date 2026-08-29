# TRNM Agent Prompts A12-A14 v1

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

## A12 — G2B Agent, Capability and Task Market

```text
Start and own package G2B_AGENT_MARKET_V1 for Gate G2B.
Mission: Close identity/controller/session keys, attenuated capabilities, budgets, nonce lanes and the complete Task/Bid/Lease/Escrow/Checkpoint lifecycle.
Upstream dependencies: A08, A10.
Owned surfaces: trillionnium/crates/trnm-poco-agent-market-v1/**; Agent/Market protocol/contracts/vectors; Agent/Market focused gates.
Forbidden surfaces: verification decisions; settlement asset movement; claiming local store roots as global state.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: root/controller/session rotation/revocation; capability attenuation and shared budgets; parallel nonce lanes and payer nonce; pause/resume/migrate/cancel/timeout/refund; artifact/profile immutability; AgentTransactionV1 authorization.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Capability escalation, replay, expiry, missing scope and profile downgrade fail closed.; Every transition is versioned and idempotent.; No local candidate root is presented as global authority..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A13 — G2D Deterministic Execution, MVCC and Fees

```text
Start and own package G2D_EXECUTION_MVCC_FEE_V1 for Gate G2D.
Mission: Close deterministic object-aware parallel execution, serial equivalence, resource receipts and hot-key-free block-end fee deltas.
Upstream dependencies: A08, A10, A12.
Owned surfaces: trillionnium/crates/trnm-poco-mvcc-fee-v1/**; execution/MVCC/fee contracts and vectors; execution focused gates.
Forbidden surfaces: settlement movement; verification decisions; global JMT commissioning without G2F.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: real parallel worker pool; canonical read/write/version commitments; deterministic retry under conflicts; full resource schedule; Agent nonce advancement; ExecutionReceiptV1 and JMT proof interface.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Worker count, timing and retry order never change state/receipt roots.; Success, reverted and out-of-resource are explicit.; Execution cannot settle, reward, slash, refund or create PoCO weight..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A14 — G2C Verification and Challenge

```text
Start and own package G2C_VERIFY_CHALLENGE_V1 for Gate G2C.
Mission: Launch one narrow deterministic re-execution candidate profile and close result/challenge/outbox/expiry/revocation/appeal semantics.
Upstream dependencies: A08, A10, A11, A12, A13.
Owned surfaces: trillionnium/crates/trnm-poco-verify-challenge-v1/**; verification profiles/contracts/vectors; verification focused gates.
Forbidden surfaces: settlement asset movement; automatic profile fallback; subjective evidence as objective finality.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: deterministic re-execution profile assurance case; canonical profile registry; DA evidence binding; concurrent/duplicate challenges; expiry/withdraw/appeal; disabled-profile rejection; outbox/retry/recovery.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: No ambiguous Valid status crosses profiles.; Disabled, expired or missing-evidence profiles reject canonically.; Decisions end only in ResultFinal or ResultRejected.; No automatic downgrade to StakeQuorum or subjective evaluation..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```
