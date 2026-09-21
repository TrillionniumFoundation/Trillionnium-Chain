# M06 Execution, MVCC and Meter technical specification v1

Status: implementation contract with explicitly planned extensions; no activation.
Primary owner: M06. Consumers: M02 proposal validation, M07 state, M08 commit,
M10/M11 application operations, M12 fees, and M15 composition.

## Authority

Resolve [documentation authority](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md).
The native `bft-v0` route retains CEV0, native runtime transaction semantics,
frozen proposal validity and authenticated consensus parameters. The AI candidate
uses the separate [v1 execution and fee draft](../protocol/poco-ai-native-v1/08-coordination-settlement-execution-and-fees.md).
Candidate Borsh layouts are not new CEV0 layouts or a globally frozen CEV1 codec.

Existing source anchors, relative to `trillionnium/crates/`, are:

| Component | Source and operation | Authority |
|---|---|---|
| Native body execution | `trnm-native-execution-v0/src/complete.rs`, `native_parallel.rs` | Compute a complete prepared application plan |
| Native persistence | same crate, `durable.rs`, `store.rs` | Prepare and replay plans; final commit requires M08 authority |
| AI object executor | `trnm-poco-mvcc-fee-v1/src/engine.rs` | `execute_block_with_workers`, sequential `execute_block` |
| AI persistence | same crate, `store.rs` | `MvccFeeStoreV1::preview_before_vote_v1`, `execute_block`, `fresh_confirm` |
| AI encoding | same crate, `types.rs`, `codec.rs` | Candidate exact field order, hashes and strict decode |

The AI executor is a bounded Add/Transfer/Revert kernel, not an arbitrary VM.
Its input has no public transaction signature or nonce authorization field.
M01/M05/M10 must authenticate the outer transaction before the node can treat
this computation as proposal-valid. Calling its store directly does not prove that.

## Interfaces

`MvccBlockV1` contains schema version, protocol context, block ID, target height,
expected parent height/block ID/root, and ordered transactions.
`MvccTransactionV1` contains schema version, derived ID, gap-free transaction
index, fee payer, sorted declared reads/writes, compute limit, maximum fee and
one `ObjectProgramV1`. `ObjectStateV1` binds object ID, version, value and closed bit.

`derive_transaction_id_v1` hashes the exact tuple excluding the supplied ID in
domain `trnm.poco-ai.mvcc-transaction.candidate.v1`.
`derive_block_id_v1` hashes context, target/parent coordinates and complete
transactions in `trnm.poco-ai.mvcc-block.candidate.v1`.
The supplied IDs must equal recomputation. Context is not selected from an
untrusted proof; genesis/profile/chain/version must match installed authority.

The successful computation returns the complete resulting object map and
`MvccBlockReceiptV1`, including ordered transaction receipts and roots.
Transaction receipts contain read/write sets, resource usage, fee deltas,
status and error-class semantics. The three receipt statuses are `Success`,
`Reverted`, and `OutOfResource`. A returned speculative object is not a
`ConfirmedMvccBlockV1` and cannot be published as committed state.

Native input is the exact complete body and authenticated parent application
snapshot selected by the native owner. Native `RecordingViewV0` records full
`Option<StateObject>` dependencies, including absence, type, version and bytes.
Never convert a failed storage read into an absent object.

### Other owned execution packages and their exact boundaries

`trnm-native-application` is the host-neutral port, not an executor or database.
`NativeApplicationV0::execute_block` accepts `NativeBlockExecutionRequestV0`
with chain/genesis, parent `ApplicationHeadV0`, block/height/time, validator set,
ordered transaction bytes and expected payload/state/receipt/evidence roots.
`commit_block` consumes the separate commit request; computing an executed block
does not confer commit authority. `NativeFinalizationQueueV0` retains bounded
intents/fork/readback facts and must preserve retry disposition across owner
recovery. Current structural maxima are 4 MiB body, 16 MiB executed artifact,
and 1,024 queue entries; the selected authenticated profile may be stricter.
Artifact encode/decode in `src/artifact.rs` binds version/domain and rejects
trailing/noncanonical bytes. Host unavailable and deterministic invalid outcomes
stay distinct through `NativeBoundaryErrorCodeV0` and the execution result.

`trnm-runtime` transforms a `CanonicalTxV1` plus `ExecutionContext { height,
signer_id, signer_role, payload_len }` and state view into `RuntimeReceipt`.
Its mutations carry object key/type, expected version, next version and exact
value bytes; receipt carries gas, fee and events. The host authenticates signer
context before entry. Use `try_execute_v0`/`TryStateViewV0` for storage-backed
execution and `try_estimate_resources_v0` for admission estimates. An estimate
does not authorize a transaction. `RuntimeExecutionAttemptFailureV0` preserves
typed read unavailability separately from deterministic invalidity; no failed
call returns mutations. Nonce/version, funding, role and task-state checks in
the runtime remain necessary even when an upstream admission check succeeded.

`trnm-executor` supplies `detect_conflict`, `build_parallel_groups` and grouping
profiles/strategy selection over transaction access declarations. Its product
is a schedule, not a receipt. Group metrics and adaptive decisions cannot enter
consensus hashes. M06 rechecks actual runtime dependencies and original order;
an incomplete declaration cannot authorize a hidden read/write or different
result. Grouping has no durable state; recompute it after restart from the exact
body. Bound input by the selected body's transaction/access limits before building
the conflict graph; a local scheduling failure uses canonical execution or
unavailability, never a new transaction ordering.

`trnm-poco-global-execution-v1` joins DA, agent-market, verify-challenge, MVCC-fee
and settlement stores through `GlobalExecutionSourcesV1`. Its existing sequence is:
fresh authenticated DA retrieval → each plane's real inert preview → recomputed
`CandidateCompositeCommitmentV1` → `prepare_before_vote_v1` exact checkpoint CAS →
private `PreVoteExecutionReadyV1`. After independently verified Order finality,
`apply_finalized_candidate_and_issue_owner_v1` replays exact plane commands and
issues `WholeNodeFinalizationOwnerV1` only after fresh source-bound readback.
`finalize_terminal_facts_v1` binds the final composite commitment and terminal
facts; a caller-supplied root cannot replace this sequence. The manifest-bound
v2 input additionally revalidates the certified batch and five-plane source cut.

The global store caps a batch item at 4 MiB and each command plane at 256 entries,
in addition to lower plane limits. `DaSourceChanged`/`SourceCutMismatch` reject
mixed source cuts; `CandidateCompositeRootMismatch` rejects a claimed preview;
checkpoint race/stale/conflict cannot overwrite a winner. Reopen through
`recover_prepared_ready_v1` or `recover_finalization_owner_v1`, reauthenticate
all retained predecessor/target facts, and fence tamper/recovery mismatch.
Sequentially replaying five databases is not atomic production application
commit. Whole-node crash recovery and M08 publication remain explicit acceptance
obligations; neither a ready handle nor a stable preview is finality.

## State machine

For a block, execute these stages in order:

1. Check profile/context, target identity and exact parent height/block/root.
2. Check block and transaction counts before allocating worker results.
3. Require gap-free transaction indices and exact derived IDs. Require each
   access list to be strictly ordered and unique under the candidate comparator.
4. Validate fee payer, object versions, supported program and resource declarations.
   Outer authorization/nonce validity remains the selected runtime's obligation.
5. Give workers an immutable parent view. A worker computes the complete local
   program, read dependencies, resource usage, fee and tentative successors.
   It returns either private computation or a retained failure, never a receipt
   that independently authorizes canonical publication.
6. Visit transactions in their original order. Compare every recorded dependency
   with the overlay produced by earlier accepted transactions. AI comparisons
   check object version and value hash; native comparisons check the full object.
7. Reuse only an unchanged dependency set. Otherwise run the exact transaction
   once against the current canonical overlay. A parent-snapshot failure is
   rechecked too: a preceding credit may repair insufficient funds.
8. Validate/stage all mutations atomically, calculate the canonical receipt,
   accumulate fee deltas and advance the overlay. A block-level error discards
   all earlier tentative block changes and fees.
9. Seal roots/ordered receipts only after all required transitions succeed.
   Send the immutable plan to M07/M08; workers never apply durable state.

Native PoCO/validator transitions are serial barriers and clear queued
speculation. The native transfer fee-rebasing optimization applies only when
its proven transfer predicate and dependency checks hold; it is not a general
permission to ignore writes to the fee collector.

The native parent view now proves lifecycle and runtime keys on demand. Worker
admission verifies/decodes an envelope once, then actual runtime attempts discover
dynamic account/task dependencies using a finite prefetch map. A missing entry
requests an owner-thread JMT proof; an explicit `None` means a verified absence.
The same frozen parent transaction supplies all rounds. Workers never receive
the SQLite connection. The canonical loop still checks complete read values and
re-executes stale successes/failures against earlier mutations. Object revision
is a per-mutation counter and may exceed consensus height; this optimization
does not add a height bound to object revision.

Only PoCO operations, scheduled cutoff refresh or an authenticated epoch prefix
request the complete bounded namespace projection. Ordinary runtime and empty
non-cutoff blocks no longer pay for unrelated live objects. PoCO's remaining
whole-tree enumeration and frozen manifest/authority checks are unchanged.

## Security

### Metering and fee computation

The AI kernel requires exactly four `ResourcePriceV1` entries, sorted by
resource class/resource ID/unit: ordered bytes `(0,1)`, read bytes `(2,1)`,
write bytes `(3,1)`, and compute `(7,3)`. Each carries numerator, denominator,
minimum and maximum charge. Denominator must be positive; minimum must not
exceed maximum; arithmetic is checked `u128`, never floating point.
For usage q and a resource price `(n,d,min,max)`, the current kernel computes
`p = checked(q*n)`, `rounded = p/d + (p%d != 0)`, then
`charge = clamp(rounded,min,max)`. Sum all four charges with checked addition.
Each destination receives `floor(fee*numerator/denominator)` and all residual
units go to the named remainder destination. Changing these rules requires
a new authenticated fee profile and vectors, not a scheduler flag.

Current program compute costs are Add=10, Transfer=20 and Revert=5. Add/Transfer
with too small a compute limit produce `OutOfResource` and meter that limit;
the explicit Revert branch meters its fixed 5 units under the present kernel.
Read bytes sum exact encoded dependency objects; write bytes account for the
successful program's writes plus fee-payer mutation. Do not reinterpret this
bounded candidate meter as a gas schedule for arbitrary programs.

The development replay profile is the exact genesis constructor in
`trnm-poco-mvcc-fee-v1/src/tests.rs::genesis`: byte classes use 1/128,
compute uses 1/10, each minimum 1 and maximum 100; fee destinations receive
3/4 and 1/4, with residual integer units assigned to the second destination.
Its test chain and keys are fixtures, not deployment defaults.

A commissioned candidate instance supplies the entire `MvccFeeGenesisV1`:
context, nonzero store/initial-block identities, initial height, sorted objects,
the four prices, sorted destination splits and explicit remainder destination.
No fee schedule may be inferred from a missing field. Destination fractions
and remainder handling must pass `validate_genesis`, and the exact serialized
genesis/profile hash is retained with the store. A changed schedule requires
the explicit upgrade path; reopen with altered values rejects.

`Reverted`/`OutOfResource` retain the selected failed-work fee semantics but
publish no application writes. `max_fee` is an authorization ceiling, not a
request to charge the whole maximum. Local worker allocation failure or local
CPU pressure is `Unavailable`; it does not change canonical fee or receipt status.

## Resource bounds

| Boundary | Existing bound or selected development rule |
|---|---|
| AI block transactions | `MAX_TRANSACTIONS_V1 = 256` |
| AI access width | `MAX_ACCESS_WIDTH_V1 = 64` |
| AI workers | 1 through `MAX_EXECUTION_WORKERS_V1 = 64` |
| Native speculative batch | At most 32 transactions and 8 workers; not a whole-block limit |
| Native prefetch/reuse | At most64 recorded reads/256KiB per attempt; 2048 keys/8MiB per batch; at most65 discovery rounds. Failure abandons speculation, not the transaction. |
| Native transaction/body limits | Exact authenticated bft-v0 parameters and codec limits |
| Candidate development host queue, planned | One executing block, two queued bodies; reject admission of a third queued body |
| Candidate development host retained body bytes, planned | 16 MiB total, additionally subject to the smaller selected protocol limit |

The planned host limits are local scheduling controls, not consensus validity.
Missing workers fall back to canonical native execution where already supported;
an unsupported AI worker count returns `InvalidBounds`. Allocation/queue refusal
must occur before retaining the new body. Never drop an already committed plan.
Large-state/long-history persistence still needs measurement. M07's explicit
ordinary schema5 uses actual state/replay deltas; schema3/4 retain their bounded
snapshot formats, and PoCO enumeration remains a separate cost.

The default-off `incremental-epoch-candidate` feature now computes the first
new epoch block against the actual incremental checkpoint reader. Its only
root alias is C+2's empty path to C's real root; inherited child versions remain
unchanged. Existing authenticated config/usage rollover and user transactions
produce one C+3 state delta and actual epoch-artifact-v1. The signed C8→C11
fixture matches the schema4 root and receipts, persists real P, and reopens it.
Schema6 currently prepares this first block only; descendant execution, strict
finality commit and the public/Core adapters remain fenced. This is not evidence
that a full two-epoch node run is enabled. PoCO rollover's bounded namespace
scan remains intentional and separate from ordinary per-key execution.

## Persistence and recovery

Use actual `MvccFeeErrorCodeV1` values, not invented wire codes:

| Error family | Effect and recovery |
|---|---|
| `InvalidContext`, `IdentifierMismatch`, `NonCanonical`, `InvalidBounds` | Reject before mutation; preserve parent/root/receipt inventory |
| `UndeclaredAccess`, `DuplicateAccess`, `StaleParent`, `InvalidState` | Reject selected operation/block; never partially publish |
| `InsufficientFunds`, `FeeLimitExceeded`, `ArithmeticOverflow`, `ConservationViolation` | Preserve authoritative balances and sequence; no saturating money arithmetic |
| `StoreFailure` | Local failure; after possible commit, require fresh authoritative readback |
| `CommitUncertain` | Reopen exact source/target and return the original logical outcome only |
| `SchemaMismatch`, `TamperDetected`, `SidecarPresent`, `ThirdStateFenced` | Fence owner; do not repair by selecting whichever root is convenient |

`preview_before_vote_v1` verifies the same computation without changing any
logical durable row. `execute_block` must bind its expected predecessor, write
the exact block/receipt/object successors, commit, then reauthenticate durable
readback before confirming. Retry matches exact block and predecessor; a
different payload at the same identity is conflict, not idempotence.
Crash cuts cover before transaction, before commit, after commit/lost response,
and confirmation. Recovery accepts exactly source or target; a third state
fences. Store-local checks do not establish whole-machine rollback resistance.

### Candidate cross-epoch native execution edge

Consume M08's `AuthenticatedEpochApplicationEdgeV1`, never caller roots.
At checkpoint C the committed application version is C. Seals C+1 and C+2
produce no application execution, P row or receipt. The first new block has
consensus parent seal-2 but application parent checkpoint C; its real JMT target
label is C+3. This preserves frozen cutoff equality for actual executed blocks.

M07's `CarriedRootReaderV1` intercepts only the empty root lookup at
version C+2 and resolves the authenticated root at C. Other node paths retain
their real versions; value reads prove the gap contains no writes. The executor
must not relabel all nodes, create fake seal transactions or relax the ordinary
parent check globally. Build the first plan in a separate authenticated edge
variant. Publish C+3 only after normal durable commit; the virtual predecessor
root is private construction metadata. Candidate implementation status is
described below; this does not activate the production node/Core path.

M08 now persists the first-new execution and speculative C+4/C+5 through its
explicit bounded schema-4 bridge. Its separate first-new artifact binds both
parents, and strict new-set finality commits the prepared state exactly once.
The sealed `EpochExecutionContextV1` path also prepares a later successor C+3
P, carries the complete prior lineage into the authenticated snapshot, and
commits the P, metadata CAS, and schema-8 successor-edge consumption in one
transaction. The ordinary codec/+1 path remains unchanged. This later path
is candidate-only: there is no independent C21 positive proof vector or
production Core/Safety activation, so those gates remain closed.

Before user transactions in C+3, the selected edge executor applies one fixed
system prefix: validate the authenticated old/new configuration edge, install
the new active configuration, then normalize PoCO usage buckets under
[frozen weight specification 05, section 20](../protocol/poco-bft-v0/05-poco-weights-bond-and-slashing.md).
These system writes and user writes belong to the same C+3 JMT/commit transaction.
Seals and anchor installation perform no application rollover. Historical
certificate finalization epochs remain unchanged; a partial prefix cannot
survive a failed block or be published as a separate application head.

The candidate runtime now implements this prefix in
`poco_application::begin_authenticated_epoch_rollover_v1`, consumed by complete
execution through an opaque `AuthenticatedEpochApplicationEdgeV1`. It validates
the old projection before normalization, compares the exact old set/parameters
to the edge, removes both old role-1 configuration entries, and inserts the new
role-1 set/parameters under the incoming epoch identity. The new identities
start at envelope revision 1; kind 16 increments exactly once when the whole
block seals, including a block with zero user operations. Ordinary overlay
construction still requires source+1; only the edge path admits real source C
and target C+3. This implementation does not establish Core epoch activation.

Election inputs have a separate lifetime from retained certificate authority.
The same prefix consumes all kind-16 `future_candidate_registrations`, pending
governance proposals and finalized governance approvals for the incoming epoch.
It deletes each consumed governance kind-15 entry and its role-2 parameters
companion in the same mutation set. An input naming any other target rejects
the prefix. Pending proposals never become authorization; the new configuration
comes exclusively from the verified edge, including fallback selection. This
is expiry of the live election cache, not rewriting historical facts: the
retained checkpoint still authenticates the exact old records, and permanent
nullifiers, provider registration history, certificates and their original
finalization epochs are unchanged. The existing startup validator continues to
require live election inputs to target exactly active_epoch+1. Independent
prefix tests exercise pending/approved expiry, strict candidate PoP retention
at the source, normalized target restore, and zero-operation atomic sealing.

For a child whose parent has not finalized, consume M07's private
`AuthenticatedPreparedSnapshotV1` through `AuthenticatedApplicationParentV1`.
`open_prepared_parent` verifies the immutable artifact/delta chain back to the
committed anchor and pins its fork-local read view. This permits C+4 and C+5
preparation while C+3 awaits its three-chain finality; it does not publish a
canonical root. A caller-provided root or merged sibling overlay is never a parent.

The planned public-intent adapter must also satisfy M05's `ExactIntent` or
`IdCommitment` binding during execution: authenticate all signed intent fields,
not just an extracted business payload. Its registered native profile fixes
how the complete signed intent/tx_id is committed. Until that profile has an
implemented strict decoder and vectors, reject the unsupported mapping; M13
cannot infer a full M05 tx_id commitment from a lossy native payload.

## Verification and evidence

| Case | Input and expected result |
|---|---|
| M06-DISJOINT | A=10, B=20; ordered Add(A,1), Add(B,2), funded separate payers: final A=11/B=22 and exact receipt/root equality at 1/2/4/8 workers |
| M06-STALE | A=10; Transfer(A,B,7), then Transfer(A,C,7): second must see A=3; it cannot publish a speculative success from A=10 |
| M06-REPAIR-FAILURE | A=0; prior transfer funds A, later A pays/transfers: retry the speculative insufficient-funds result against funded overlay |
| M06-ACCESS | Add(A,1) omits A from required access set: `UndeclaredAccess`, original state/sequence unchanged |
| M06-CAP | 257 AI transactions or 65 declared entries: `InvalidBounds`; worker counts 0/65 reject |
| M06-LOSS | Lose commit response then retry identical block: same logical receipt/root, no duplicate fee credit |
| M06-EPOCH, planned | C=100, seal heights 101/102, first target 103: application labels 100→103, zero seal effects; substituted edge/root rejects |

Existing source tests include `persistent_parallel_worker_counts_reopen_to_identical_canonical_results`,
`speculative_insufficient_funds_is_retried_after_predecessor_funds_payer_or_source`,
`stale_speculative_success_cannot_publish_when_canonical_payer_is_exhausted`,
and `crash_outcomes_reopen_to_exact_source_target_or_fence`.
Native `native_parallel_tests.rs` and `native_parallel_fee_oracle_tests.rs`
exercise real runtime receipts and fee reuse. Source regressions are not
independent golden vectors. For each planned case, independently derive full
encoded receipts and roots from the pinned source/profile before acceptance.
The point-read regression adds10000 unaccessed accounts and forbids full scans;
it retains identical touched keys and0/1/2/4/8-worker roots/receipts. Existing tests
also require eight actual runtime worker thread IDs, fee-rebase equality, failed
speculation repaired by an earlier credit, and canonical failure-index ordering.
The existing [MVCC case inventory](../protocol/poco-ai-native-v1/vectors/cev1-object-mvcc-fee-kernel-v1.json)
names candidate cases; it is an inventory, not a file of independently frozen bytes.

M02 reviews proposal validity; M07/M08 review plan durability and epoch edge;
M12 reviews fees and conservation.

The additional package acceptance cases are concrete: a native body of 4 MiB+1
rejects before execution; an artifact with one appended byte rejects decode;
a runtime account read failure returns unavailable rather than a default account;
a stale expected object version yields no receipt/mutations; moving one global
source between preview and prepare rejects the source cut. Replay the runtime
tests `failed_account_read_is_unavailable_before_default_account_semantics`,
`execute_errors_return_no_receipt_or_mutations`, and
`nonce_and_object_versions_fail_closed_at_u64_max`, plus the native-application
artifact/queue tests and global-execution `src/tests.rs` CAS/recovery cases.
Planned epoch acceptance also interrupts between system-prefix steps and proves
that durable state is entirely C or entirely the valid C+3 result.

## Observability and SLO

Report execution-only timing separately from committed goodput, conflict and
reexecution rate, worker utilization, wasted speculative work, storage cost and
finality p50/p95/p99. Capture the exact profile, body bytes, state/history size
and worker count. Zero root/receipt/fee disagreement across worker counts is
required; it is not proof of speedup. Compare 1/2/4/8 workers on disjoint,
shared-payer, hot-object and failure-heavy mixes before changing defaults.

## Activation boundary

Only selected existing native and AI candidate operations may be invoked under
their current feature/profile closures. The epoch edge and planned host limits
need implementation and exact producer/consumer replay. Protocol byte changes,
independent oracle acceptance and production enablement remain separate decisions.


### Incremental epoch execution implementation boundary

The default-off native schema7 candidate composes the actual C+3 authenticated
config/usage prefix with changed JMT and replay data, followed by ordinary +1
execution through the actual prepared C+4/C+5 lineage. Descendants use the new
parameters and validator set recovered from strict edge evidence, not caller
configuration or the owner's original old-set defaults. Their actual native P
parent digest binds both speculative application state and command/nonce replay.
The ordinary demand-prefetch reader and real parallel workers remain active;
PoCO rollover retains its bounded namespace scan where the protocol requires
complete configuration/cache normalization.

The signed local business fixture credits the operator at11, transfers to eight
accounts at12, and compares serial and1/2/4/8-worker full roots, exact payload and
receipts on the incremental reader. Duplicate command errors agree as well.
This proves deterministic equivalence for the covered workload, not throughput
or speedup. Schema7 rejects a second checkpoint/handoff; schema6 remains
prepare-only and schema5's ordinary +1 guards have not been broadened. The M07
and M08 commit/reopen receipts do not independently grant a Core vote or node
activation.

The candidate-only node bridge exposes
`CandidateEpochRuntimeV1::ensure_incremental_epoch_commit_owner_v1()`. It may
run only after the complete initial owner cut is joined and an explicit schema6
native edge exists; it calls the native
`DurableNativeApplicationV0::ensure_incremental_epoch_commit_owner_v1(&edge)`
under the native owner lock, then rechecks Safety, signer, retirement,
checkpoint, and native identities. The call is resumable across a lost response
and never executes a block, verifies finality, signs, broadcasts, or enables the
default node. Schema5→6 migration remains a separate explicit operation.

Recovery is binding-aware even while the schema7 owner is still a singleton:
`recover_incremental_epoch_edge_for_binding_v1(binding)` audits the complete
owner row, checks that `binding` is the active persisted authorization ID, and
only then reconstructs the checkpoint/handoff evidence. A foreign, stale, or
future binding fails before checkpoint reconstruction. The no-argument recovery
entry point remains compatibility-only; it must not be used as evidence that
schema7 supports multiple edge owners. A versioned edge-history record and
lineage-aware storage/replay contract are required before the singleton guard
or the first-new `count == 0` restriction may be relaxed.

Schema4 now exposes the read-only `read_epoch_edge_history_v1()` contract and
the indexed `recover_epoch_application_edge_at_index_v1()` seam. They return
only a recursively audited, owner-affine history: every consumed P must carry
the complete ordered lineage, while a second unconsumed row, duplicate height,
corrupt lineage, missing predecessor, or concurrent mutation fails closed.
This closes the observation/recovery contract, and phase-1 recovery binds the
consumed C+3 P to the current metadata head. The explicit schema8 M08
consumer durably commits a strictly verified later checkpoint, retains all
CEV0 preimages for restart auditing, and installs a separate checksummed
successor-edge row with its own binding and post-checkpoint context digest.
The C+3 path is implemented as a candidate owner seam with schema-9 proof
retention, a local C21 positive fixture and three crash cuts; independent C21
vectors and production activation remain acceptance gates.
The same full-snapshot candidate can prepare ordinary C22/C23/C24 after C21
through recovered sealed legacy/later contexts and strictly commit C22 with
its ordinary new-set proof. Every descendant preserves the entire lineage,
the exact application parent and target configuration. It does not consume
the later successor again or create another first-new proof row. This does
not extend incremental schema7 to a second crossing or permit repeated
later-to-later handoffs.

`DurableNativeApplicationV0::inspect_later_epoch_checkpoint_context_v1()` is
the owner-affine context boundary. It re-reads the consumed edge lineage and
authenticated epoch-context row, verifies the context digest and canonical
active validator set/parameters, and derives the next checkpoint, seal-1,
seal-2, first-new height and exact cutoff geometry (the fixture yields
18/19/20/21 and cutoff 15). `verify_later_epoch_checkpoint_finality_v1()` now
strictly decodes the later checkpoint parent/header, two-seal proof, commitment,
old/new configuration preimages and handoff kernel, applies the bounded CEV0
budget and strict Ed25519 checks, and revalidates the owner context after the
cryptographic work. The feature-gated fixture proves H11-H17 ordinary old-epoch
execution followed by C18/S19/S20 evidence and rejects a commitment-byte
mutation. The checkpoint observation remains read-only; the separate
`prepare_later_epoch_first_new_block_v1` and `commit_epoch_finality_bytes_v1`
seams perform C+3 preparation and strict proof/commit, while the legacy
`require_later_epoch_checkpoint_bridge_v1()` continues to fail closed. M08's
schema8 commit binds the checkpoint P/state root and installs the separate
successor-edge row before the later checkpoint becomes durable.

The post-C18 edge seam is intentionally explicit:
`inspect_later_epoch_application_edge_requirements_v1` derives the successor
activation binding from retained strict evidence and returns the exact
C18/C+2/C+3 geometry while keeping the pre-C18 proof-context digest distinct
from the recomputed post-C18 successor-context digest. Schema8 atomically
persists that binding in `native_later_epoch_edge_v1`; `require_...` reopens it
only after a complete cold audit and returns an owner-affine capability. The
sealed transition-context trait carries the coordinates and strictly decoded
old/new configuration into complete and incremental execution. C+3 preparation
atomically stages a versioned P, and finality commit CASes metadata/P and
consumes the successor edge; phase-1 validation binds the consumed P and
survives reopen. The old H17 edge is rejected once the application head is
C18. Independent C21 proof vectors, external rollback anchors and production
Core/Safety activation remain outside this candidate owner.
