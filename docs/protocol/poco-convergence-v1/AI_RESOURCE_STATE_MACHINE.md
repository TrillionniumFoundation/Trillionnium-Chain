# PCC1 — AI resource and task state-machine contract

Status: **candidate application-profile extension; not implemented or activated**.
Read with [the consensus/authority contract](README.md) and
[proof migration](PROOF_MIGRATION.md). This is not a second consensus network.
Authorization, result acceptance and settlement are business stages maintained by
one deterministic PoCO-BFT ledger, not three independent quorums.

## 1. Existing contracts and extension boundary

The `../poco-ai-native-v1/` identity, task/lease, receipt/verification, availability,
execution/fee and sync specifications remain the field-level baseline. Preserve
their exact task, lease, attempt, capability generation, session generation,
profile version/hash, artifact and nonce bindings; do not treat similarly named
fields as aliases. PCC1 adds the integration obligations below. A disagreement
requires a versioned registry/profile correction before activation, not precedence
selected dynamically by a node.

PCC1 logical records below are proposed additions, not reuse of existing wire
kind numbers. Their complete canonical registry entries, encodings, error codes
and positive/negative cross-language vectors must be frozen with the new
application profile. The Python model uses no protocol encoding and issues no
consensus capability. Its resolved-result input is an abstract precondition,
not a proposed API allowing callers to assert correctness.

## 2. Replicated records and invariants

Every record carries schema/profile identity and full chain context. Integer
arithmetic is checked, no floating-point balance or nondeterministic rounding.
Maps and lists use exact canonical ordering and finite limits.

| Logical record | Required contents, in this logical order |
|---|---|
| ResourceBudget | resource class/id, capacity, reserved amount, unit, meter/profile hash, revision |
| Capability | principal, grant id, scope, allowed operations/objects, budget ceiling, valid-from/to, revocation generation |
| NonceLane | principal, capability generation, session grant/generation, lane, next nonce, retained replay floor |
| Task | task id, revision, owner, sponsor, capability binding, dependencies, model/input commitments, immutable verification/settlement profile refs, maximum escrow, deadline schedule, phase |
| Lease | lease id, task id, attempt, provider/key, generation, resource reservation ids, start/finish bounds, status |
| Obligation | obligation id, task/lease/attempt, type, resource vector, evidence commitments, next service height, hard terminal height, retention horizon, predecessor/revision, status |
| ExecutionReceipt | exact existing receipt identity, provider, environment, model/input/output, transcript/meter commitments, proof/profile binding and nonce |
| Settlement | settlement id, task/lease/attempt, authorized result or terminal transition, escrow source, exact payout/refund/fee amounts, consumed obligations, applied revision |
| RetentionRecord | artifact id, bytes, storage responsibility, minimum horizon, challenge dependencies, release condition, revision |

Local resource telemetry never becomes any of these authoritative values. Private
prompts, model weights and raw personal data need not be public state. Commitments
are not confidentiality by themselves, and access permission must be explicit.

Asset conservation is checked per asset and escrow account:

```text
cumulative escrow deposits
  = current escrow + cumulative provider payments
    + cumulative fee/penalty transfers + cumulative refunds
```

A refund credited back to a spendable account is not counted a second time as
newly minted value. No application transition may spend the same escrow revision
or resource ticket twice. A task settling once may retain storage liability later.

Lifetime transfer volume is not bounded by the current monetary supply: the same
principal can be refunded and reserved repeatedly. A fixed-width diagnostic
counter MUST NOT be an extra validity condition on mandatory settlement. Exact
account balances and each settlement remain checked and exact. Non-authoritative
cumulative diagnostics may saturate with an explicit saturation flag, after which
they are only lower bounds; they cannot authorize payment, prove conservation or
replace the exact settlement history. The abstract model uses this convention for
`refunded` and includes the flag in replay comparisons. Wrapping a balance, dropping
a refund or rolling back block service because a diagnostic is exhausted is forbidden.

For every resource class r:

```text
reserved[r] = sum(exact unreleased obligations charged to r)
0 <= reserved[r] <= capacity[r]
```

Enforce aggregate sums, not only pairwise conflict tests. Three jobs reserving
40 units each cannot be admitted to a 100-unit capacity even though each pair
fits. Separate caps exist for task/obligation counts, bytes, proof work, challenge
work, event count, retention and pending system-service work. Zero-cost tasks
cannot bypass count/byte caps.

The task-slot cap counts outstanding responsibility, not lifetime admissions. A
slot remains occupied through settlement AND required retention; it is released
only after both are terminal. A completed, retention-released historical record
must not consume an active slot indefinitely. Releasing that slot does not erase
the task identity, permit nonce replay or make an old settlement executable again.
Production storage must separately bound hot history and preserve authenticated
archive/replay-floor commitments. The Python dictionary retains historical records
for replay tests; it is not a bounded production archive implementation.

## 3. Authoritative time and deterministic execution

H is the candidate block's execution height, derived from its authenticated
parent, not the serving node's latest observed finality. A local timer is not a
task deadline. All effects remain speculative until their containing block is
finalized; off-chain workers act on a verified authorization/lease receipt.

Each block executes mandatory bounded system work first, then user operations in
canonical consensus order. Every user operation observes prior operations' writes.
A failure commits no partial task mutation, escrow debit or resource reservation;
any charged transaction fee follows the separately pinned deterministic fee rule.
Parallel execution must produce exactly this sequential outcome.

For a deadline D, a result is eligible at H <= D. It is late at H > D, even if
bounded expiry processing has not yet visited the task. This boundary prevents a
backlog from extending a lease. New due dates must be strictly in the future
relative to their creation transition unless the transition is an immediate
terminal/system action. Deadlines cannot be backdated to jump a service queue.

## 4. State transitions

The initial profile uses at most one active lease per task and one accepted
receipt per lease/attempt. A retry creates a distinct incremented attempt with
fresh reservations; it cannot overwrite the previous attempt or reuse its receipt.

```text
Created -> Funded -> Leased -> Running -> ReceiptSubmitted
                                      -> ResultAccepted -> ReadyToSettle
                                      -> ResultRejected -> ReadyToSettle
         failure / cancellation / timeout -> ReadyToSettle
ReadyToSettle -> Settled -> RetentionReleased
```

Created may be local-only; Funded is the first accepted chain state. The explicit
transition registry, not an arrow alone, determines authority:

| Transition | Required facts and atomic effects |
|---|---|
| Submit/Fund | validate owner/sponsor capability and nonce; dependencies and profiles; debit sponsor; reserve all future obligation classes and a task slot; create escrow/task/expiry index atomically |
| Lease/Start | exact funded task revision; eligible provider; fresh attempt/generation; finite execution bound; bind existing reservation and create lease |
| SubmitReceipt | active lease/attempt; authorized provider/key; exact model/input/environment/profile; bounded artifact/proof bytes and required availability; consume provider nonce; store one claim, not final correctness |
| Verify | deterministic pinned verifier over the exact public statement; bounded metered work; set result status and a settlement-ready event only when its acceptance policy allows |
| Cancel | authorized cancellation scope and exact predecessor; apply the task's immutable cancellation policy; prevent further old-attempt receipt acceptance |
| Expire | mandatory system transition at H > the current stage deadline; record timeout, release/transfer responsibility under pinned rules; do not fabricate fraud evidence |
| Settle | final deterministic result/terminal decision; no open required challenge; consume exact escrow/obligation revisions once; emit payment/refund and settlement record atomically |
| ReleaseRetention | minimum horizon elapsed, all referenced disputes/obligations resolved and required archive policy satisfied; release storage charge without reviving old authorization |

A malformed or invalid proof submission is rejected and charged according to the
bounded admission/fee policy; it need not make the underlying task irreversibly
failed. A genuine failure report is a signed provider claim handled by the pinned
verification policy. Neither unauthenticated reports nor local verifier overload
can create a final result.

For the initial minimal extension, use a fixed-price all-or-refund business
policy: objectively accepted result pays the agreed price (not above escrow),
refunds unused escrow, and otherwise refunds the business escrow. Transaction
fees are separate. Timeout is not cryptographic proof of fraud and does not
justify invented slashing. Other cancellation compensation, partial-metered
payments, fraud penalties or optimistic disputes require separately enumerated
profile rules and accepted tests before use.

## 5. Verification profiles and artifact responsibility

Task creation pins `profile_id`, `profile_version` and `profile_hash`. The verifier
program/circuit, public inputs, arithmetic/quantization environment, validity
predicate, maximum cost, permitted outcomes, evidence retention and settlement
policy are fixed by that profile. A model update cannot change an in-flight task.

The first production candidate may activate only profiles with a deterministic,
bounded verification predicate and accepted vectors. General inference is not
rerun by every validator. TEE, probabilistic sampling, optimistic challenges,
external oracles and human arbitration are separately labelled trust models and
remain disabled unless their explicit profile, cost/failure policy and activation
are accepted. A TEE quote does not prove external input truth; a computational
proof does not prove subjective quality beyond its statement.

A provider signature attributes a claim. A QC orders a transaction. A full
finality proof confirms the resulting chain fact. None alone proves that an AI
answer is true. RPC metadata must identify the exact accepted verification class.

Artifacts must bind exact bytes/codec, digest, size, task/attempt and availability
responsibility. Required evidence is retained through the longest applicable
verification/challenge/appeal horizon. If a proposed horizon exceeds reserved
capacity, extend/reserve atomically before accepting the extension, otherwise
reject it. Settlement releases verification/challenge work only after it is no
longer required; storage remains reserved until retention release.

Availability failure has an explicit task retry/failure disposition. It never
permits different honest nodes to independently redefine an already-finalized
result. Certificates must specify retrieval, repair, operator responsibility and
expiration; an opaque content hash or a URL is not such a certificate.

## 6. Mandatory service and bounded debt

The active profile fixes finite positive per-block service capacities for:

1. expired stage deadlines;
2. result/terminal settlement-ready events;
3. expired retention obligations.

Each category is a deterministic ordered index keyed by `(due_height, task_id,
obligation_id)`; settle-ready events use their creation height, not a caller's
priority. Process the first K eligible entries in each category, or all when
fewer exist. The selected prefix and its deterministic effects are mandatory
block validity, including blocks with no user transactions. A proposer cannot
omit a due refund to make space for more admissions. A phase transition removes
its previous index entry before creating another; a completed entry is consumed.

Block byte/work budgets reserve enough capacity for the worst-case K system
transitions and proof of the due prefix. Remaining capacity serves user work.
Reducing system capacity to zero, accepting negative/overflowed reservations, or
lowering capacity below existing commitments is invalid. Separate local queues
protect signing, recovery, proof verification and new submissions.

With at most N already-due entries in a category, capacity K > 0, no backdating,
and continued valid block production, those entries are processed within at most
ceil(N/K) category-service blocks. This is a conditional service bound, not a
wall-clock bound, admission-fairness proof or promise that AI computation succeeds.
A finite cascade through expiry and settlement has the sum of the stage bounds.
Task execution/verification deadlines guarantee terminal handling when a provider
or proof generator disappears. The profile must bound the number of stages and
retries to prevent an infinite extension chain.

New tasks cannot be admitted without future-work budget. Limits do not themselves
establish physical service capacity; multi-host load and recovery tests must qualify
that capacity. Refusing all tasks or always timing them out is not successful
service: measure successful verified settlement, acceptance rate, rejection reasons,
cancellations, and per-class tail latency separately. External task availability
and fair eventual inclusion assumptions must be explicit for success guarantees.

## 7. Concurrent agents and access discipline

Nonce lanes isolate otherwise independent authorized operation streams. Every lane
is scoped to principal, capability generation and session-grant/generation;
reusing a lane number under another scope cannot inherit permission. Nonces are
checked and cannot wrap. Retained replay floors protect pruned history. A capability
revocation affects subsequent ordered operations according to a pinned rule; it
does not silently confiscate already-reserved escrow or rewrite prior finality.

Reserve funds and every resource dimension atomically in the same state transition.
Read/write declarations are checked against actual deterministic accesses. Sponsor
balances, shared verification budgets, grants and revocation records are conflicts
even when business objects differ. Full-order consensus with deterministic parallel
execution remains the baseline; no local locks may bypass that order.

Partitioned quota tickets may be an optimization, but transfers, unused allocation,
expiry and recovery must conserve the global total. The initial design does not
assume pairwise compatibility or unlimited independent capacity.

Off-chain calls use task/lease/attempt/request identifiers and idempotent providers
where possible. Consensus cannot make an external non-idempotent API execute
exactly once; record receipts and use an explicit compensation policy. Secret
material and private payloads do not enter consensus telemetry.

## 8. Finality, restart and upgrade

Expose three distinct business facts: authorization finalized, result accepted
under profile, and settlement finalized. They may occur in different blocks or,
where policy permits, the same block, but share one finality definition. A local
mempool receipt, speculative task state or ordinary QC is not any of them.

Checkpoint/export includes task and attempt revisions, escrow, resource counters,
nonce floors, capability generations, profile bytes/hashes, outstanding evidence,
service indexes and retention responsibility. Rebuild indexes from authenticated
state and compare roots before service. A duplicate receipt, recovery callback or
settlement request cannot release resources or pay twice.

An epoch switch carries all these obligations. New validators must retain the
verifier versions and data access needed for outstanding tasks. If this is not
possible, the transition is rejected or tasks are drained under their old pinned
rules before transition. A governance upgrade cannot use a new verifier to
retroactively relabel an old result. Migration follows PROOF_MIGRATION.md.

## 9. Required conformance and explicit gaps

Required cases include aggregate-vs-pairwise overcommit, every nonce scope, shared
sponsor funds, capability revocation races, rejected-operation no-write behavior,
receipt/profile substitution, late responses at the exact boundary, duplicate
payments, physical restart, service-prefix omission, cancellation/result ordering,
storage retained after settlement, profile upgrade with outstanding tasks, malicious
verification floods, and operation with all AI optimizers disabled. Also retain
maximum-principal refund recycling, admission after more than one lifetime of task
slots, retention-boundary slot reuse and archived-task replay counterexamples.

The included Python ledger checks only accounting, a simplified direct-result
profile, finite expiry/settlement examples and replay behavior. It does not implement
provider/capability signatures, chain codec, task dependencies, real proof verification,
challenge adjudication, production ordered indexes, pruning or the full lifecycle.
Production Rust transitions, byte registries, independent vectors, public APIs,
real network/recovery and profile activation remain open. Do not replace any of
those with caller-supplied booleans because the arithmetic model has such an input.
