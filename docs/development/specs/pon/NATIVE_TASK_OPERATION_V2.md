# Prospective native Task operations v2

## Implemented boundary

M12 `native_budget::task_operation_v2` records a prospective operation before its
result exists. It uses an actual new
[funded service contract](FUNDED_SERVICE_TASK_V1.md), and later binds the real
provider receipt and ordinary native payment. The original Task escrow remains
the sole monetary owner. The v2 journal neither credits accounts nor issues money,
changes fees, creates a new budget from a refund, or awards a learning bonus.

This opt-in implementation is limited to commissioned training and evaluation
under the fresh TSC1 classical development profile and the ordinary/authenticated
Node state backends. It does not migrate V1 claims, accept old unbound Task rows,
or enable the unsupported PQ/permanent-growth combinations.

The generic owner trait is a trusted integration boundary. An arbitrary Rust
implementation can invent observations; constructing its structs is not a chain
proof or an execution permission. The actual Node adapter supplies persistent
protocol/operation ownership and verified native transition readback. Physical
target execution still requires the target's own permission, receipt validation
and operation deduplication.

## Reservation without a predicted output

`NativeTaskOperationBindingV2` freezes the following before execution:

| Field | Meaning |
| --- | --- |
| `claim` | Permanent local claim identity |
| `task` | Actual native TSC1 task instance |
| `contract_digest` | Complete frozen native contract |
| `operation` | Permanent operation identity |
| `beneficiary` | Original native provider account |
| `target_scope` | Commitment to the intended target invocation |
| `resource_cap` | Lane and resource limits agreed before execution |

The binding contains no output digest and no caller-supplied escrow amount. Node
reads the complete contract and remaining amount from the actual native owner.
A first reservation and a first begin both require a still funded, undelivered
task before its delivery deadline. The binding has a canonical Borsh encoding and
a fresh `pon-native-task-operation-v2` / `binding` hash domain. The binding tests
retain an exact encoding length and fixed hash vector.

Only one claim per native task and one binding per operation are permitted in the
journal. These identities never include a consumer epoch, and there is no epoch
reset, resource refill, cancellation-to-new-job conversion, or mutable result
placeholder. An exact second copy of a local record refers to the same underlying
claim; it is not another escrow allocation and cannot be summed as new revenue.

## Node ownership across V1 and V2

New TSC1 tasks use a Node metadata record that survives ordinary restart and chain
reorganization. The first real budget owner access pins V1 or V2 for that task.
For V2 it also pins the entire canonical binding and the operation identity.

- The actual `NativeFundingOwnerV1::observe_funding` path pins V1 before it can
  authorize a new V1 budget/claim/effect for a TSC1 task.
- The new V2 owner reserves the task for V2 and refuses an existing V1 pin.
- A V2 pin prevents later V1 funding authorization; a changed V2 claim, target
  scope, resource cap or operation is also rejected.
- A separate operation index prevents one operation from naming another task.
- The first verified provider delivery pins its actual output in Node metadata.
  A different journal or a different branch cannot replace that output for the
  same operation. The actual receipt is replayed before the pin is persisted.
- The public read-only `native_funding_observation` remains a read. Inspecting a
  funding row does not itself reserve a protocol or grant an operation.

Old Task profiles are ineligible for V2, so previously published V1 behavior does
not need a permissive migration or a new interpretation of its `subject` field.
These ownership checks apply within the actual Node owner's persistent metadata.
They are not a network-wide lock across independently provisioned Node databases.
The target owner must share the final operation deduplication boundary when a
physical operation can be submitted from multiple Node instances.

## One begin grant and uncertain failures

The M12 immediate SQLite transaction first checks its existing claim and replay
history. If there is no Begin record, it calls the Node owner. Node atomically
persists the operation's started marker before returning `new_execution=true`.
Only the first such transition can return true. A second journal with the exact
same binding, a retry after a lost acknowledgement, and an ordinary restart all
observe false once that marker exists.

M12 then appends and verifies its own Begin event, commits it, and verifies the
committed journal prefix. It returns `New` only after both owners have durable
intents and the Node response reported the first begin. If the Node marker was
already consumed, M12 can record reconciliation state but returns `Pending`.
If the local append or readback fails after Node consumed the marker, the call
returns uncertainty; retry cannot turn that into another `New`.

An existing local Begin likewise returns `Pending`, or `Done` when a completion
is already recorded. Neither result permits another dispatch. A reconciled
target receipt can complete a pending operation without creating another begin
grant. Known local record-capacity rejection occurs before consuming a Node pin.
Unexpected failure after an owner mutation is conservative: the owner marker is
retained, and recovery must reconcile it.

Returning `New` is the successful local budget/operation boundary, not a signed
global target permission. The target must independently authorize the invocation
and validate its completion receipt. Restoring both Node metadata and the M12
journal from old copies is outside this local guarantee; the physical target and
independently retained checkpoints must keep their fences.

## Completion, costs and delivery

The implemented call sequence is:

1. `reserve(owner, binding)` records the funded contract and immutable scope.
2. `begin(owner, claim)` durably records the prospective operation and consumes
   the actual Node's one-time begin marker.
3. The separately authorized target performs or reconciles that operation.
4. `record_costs` records an immutable outcome, actual resource declaration and
   all four cost categories: training, evaluation, storage and serving. The cost
   unit and measurement receipt are explicit. Resource consumption must fit the
   frozen cap; an unknown outcome retains the full resource reservation.
5. `complete` records the operation, actual output digest and target receipt
   identity. It requires the prior Begin and cost record. V2 does not authenticate
   the target receipt on the caller's behalf; its real target owner must do so.
6. `bind_delivery(owner, claim)` obtains the real provider receipt from Node and
   requires its output to equal the completed target output. The caller cannot
   supply an alternative output to this API.
7. `record_native_payment` observes the actual ordinary Task settlement, for the
   exact provider and output, through the original native payment owner.

The Node delivery adapter finds the actual provider tag 4 transaction, checks its
signature through full native replay, and compares the replayed state/receipts
with the admitted block. A row difference or a payment alone cannot substitute
for this provider receipt. Its receipt anchor identifies that earlier block;
the contract observation identifies the current active snapshot. V2 checks the
two contexts, heights and generations without pretending they are the same block.

Output binding is one-time and immutable in both the local claim and the Node
owner's first-delivery record. A second output, changed cost outcome,
changed target receipt or different settlement transaction cannot overwrite the
existing history. A completed honest `NoGain` job may record the original service
fee after its delivery and actual payment are verified. That result has no
learning improvement bonus. Invalid, cancelled or unknown outcomes cannot be
promoted into an accepted v2 service payment by relabeling the cost record.

Recording four declared cost categories does not prove physical metering, fair
pricing, independent evaluation or positive net benefit. The metering/evaluation
owners must supply those actual materials; no true flag or synthetic measurement
is inferred from the local journal.

## Durability and current-chain status

V2 uses fresh `task_operation_meta_v2` and `task_operation_events_v2` tables,
application id, schema version and event hash domain. Existing V1 database files
are refused, and V1 refuses the new namespace. Each update checks the exact schema,
configuration, bounded canonical events, contiguous sequence and hash-chain head,
then performs durable readback. Schema additions, broken roots, changed context
and truncated checkpoints fail closed.

The six possible events for one claim are Reserve, Begin, Costs, Complete,
Delivery and Payment. There is no event that releases its operation identity or
rewrites a completed output. `checkpoint` and `verify_checkpoint` let an external
owner retain and check a journal prefix, including detection of a valid older
copy. `snapshot_after_checkpoint` checks that retained prefix and returns the
claim and current head from one SQLite read transaction. Node reconciliation
retains its own prefix floor so another consumer epoch cannot replace the
observed cost/completion history with an earlier or divergent local journal.
These checks do not make a checkpoint self-authenticating if its independent
copy is also lost.

Payment records are historical observations. `reobserve_native_payment` asks the
actual native owner whether the exact payment still belongs to the active branch.
A reorganization can remove that current membership and restore unpaid escrow;
it cannot erase the retained local cost, completion, output binding or operation
marker. A refund is not provider payment. A replay result such as `Done` means the
historical event already exists and does not assert current payment finality.

Payment readback checks the complete journal's latest persisted native anchor,
including observations for other tasks. A lower generation, or a different block,
state root or height at the same generation, is refused. A newer generation can
report the same monetary effect on another branch, including a lower height;
the original payment record and operation fence remain unchanged. The callback
is followed by a new SQLite snapshot that requires the original journal head to
remain current. An intervening WAL append causes a stale-observation refusal,
not an inferred nonpayment, another dispatch or a second fee.

This check is read-only. It does not append the returned anchor, permanently
advance a readback floor, establish independent anti-rollback custody or make
the separate Node and M12 owners atomic. A later mutation can invalidate any
returned observation. The generic owner callback still requires the original
trusted Node integration; the check does not authenticate caller-constructed
payment structs. The SQLite regression controls preserve the actual `NoGain`
service-fee record, zero learning-bonus qualification and the consumed begin
fence. `NoGain` alone is not an independently evaluated `NoUpdate` decision.

Unit tests exercise the real SQLite journal with explicitly controlled owner
callbacks, including unknown output, exact encodings, lost acknowledgements,
second journals, checkpoints, root corruption, stale anchors and resource caps.
The separate Node integration suite exercises actual signed TSC1 reservations,
V1/V2 exclusion, durable begin markers, real provider receipt replay, NoGain
payment, reopen and reorganization. These remain development fixtures and do not
certify external customer independence, physical target grants, metered costs,
model improvement or production readiness.
