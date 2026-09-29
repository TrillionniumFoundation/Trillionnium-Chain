# E2 — actual twelve-command native execution

Implementation: `trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`, in the existing
M06 owner. The M00 wire and M01 strict signatures are reused. No parallel consensus,
learning ledger or database writer is introduced. `execute_reference` remains the
independently coded Python oracle. Both implementations have the same experimental
revision3 context, not independently administered acceptance.

## Fixed ordering and validation

Execute mandatory candidate retirement, due expiry and reward maturity first. Main
transaction envelopes are decoded and strictly verified once per block against the
installed context. A private `Prepared` value owns that exact envelope, sender and
encoded length; neither JSON nor a cached Boolean constructs this carrier.

At most the requested 1/2/4/8 workers are created once per block. Distinct-sender point
operations may produce patches against one borrowed immutable state. Every key read,
including absence, is checked again against canonical preceding state. A stale patch
or speculative state error triggers exactly one canonical replay, using the same verified
envelope. Work or state errors are consumed at their canonical transaction index: a bad
later signature does not replace an earlier nonce error. No borrowed parent is mutated.

Capacity/range operations (tags2,6,8,10) execute their state transition canonically after
parallel signature preparation. This deliberately avoids retaining a prefix snapshot for
every transaction and does not claim those shared budgets are independent. Identical
sender blocks use serial state execution for the shared nonce. Consumer quota signatures
remain bound to actual quota state and are checked there; main-envelope signature reuse
must never become a generic permission cache.

All scoped workers are joined, including partial thread-creation failure and panic.
`WORKER_START`, `WORKER_PANIC` and `WORKER_RESULT` fail the candidate, not a successful
fallback. There is no resident worker service, second writer, or parallel consensus actor.
The pool lifetime is one call, not the lifetime of a chain or a local authorization.

Metrics separate worker creation, main-signature verifications, state speculation,
canonical replays, transition time and root time. `workers_spawned<=workers`; valid input
has one main-signature verification per envelope, even on conflict. Root computation
still walks the complete resulting state and is not incremental native persistence.
The retained full-state bridge and its memory/byte bounds remain explicit limitations.

## Actual read/write and range conflicts

| Tag | Reads | Writes / serialization |
|---|---|---|
| transfer | sender balance/nonce, recipient | both accounts |
| reserve_task | sender, task absence, due/pending task+quota+release scans | sender, task |
| cancel_task | sender and task owner/status | sender, task refund/status |
| record_receipt | sender and provider/task binding | sender, task output/status |
| accept_task | sender, task, provider | both accounts, task |
| contribute | sender, current model, candidate range, artifact absence | sender, contribution, nullifier |
| evaluate | sender, candidate, current model, known evaluators | sender, candidate votes/status |
| publish_release | sender, current model, bundle, each allocation, due/pending scans | sender, bundle/candidates, release, current pointer |
| claim_reward | sender, release root/nullifier/deadline | sender, release claim/remaining |
| reserve_quota | sender, quota absence, due/pending scans | sender, quota |
| consume_quota | provider, quota, consumer signature | provider nonce/balance, quota |
| register_work | sender, work-task absence | sender, work-task admission |

All commands also consume their sender nonce and fee rule. A shared sponsor, provider,
release pointer or range creates real conflicts. Merely varying recipients is not an
independent workload. Global issued/subsidy state is handled once outside parallel patches.

## Real backend entry

`TRNM_NATIVE_EXECUTOR` explicitly selects the bounded native bridge; missing, inaccessible,
failed or timed-out binaries never fall back to Python. Parent/application input is capped
at16MiB for this offline bridge, native execution is30 seconds, and returned root is
recomputed by the caller. This bridge is not a public JSON RPC nor a persistent native
consensus/persistence host. Its smaller transport capacity is explicit backpressure.

## Specific acceptance

`NativeExecutionTests.test_all_twelve_tags_match_for_1_2_4_8_workers` compares complete
maps, receipts and roots, including signed publish/claim/free-use transitions.
`test_independent_senders_commit_without_false_conflicts` requires zero retries for
independent sender/recipient pairs. `test_hot_sender_degrades_to_serial_without_speculation`
requires bounded retries. The three-generation test retains exact payout and duplicate
rejection after old-candidate removal; it does not claim three successful ML generations.

Report execution-only duration separately from process startup, work verification,
block inclusion and confirmation. A local executor speedup is never public-chain TPS.

`serial_conflict_batches=1` now identifies a whole same-sender block handled by the
serial state path; it no longer counts retired per-worker-size scheduling batches.
A sixteen-transaction common-recipient block needs fifteen canonical state replays under
the whole-block snapshot schedule, rather than fourteen under eight-item batches. Its
main-signature checks remain sixteen, not thirty-one. This changed scheduling metric is
not a consensus byte, fee, root, or success/rejection rule change.

The native bridge checks Network and full Parameters on every request and returns both identities. The caller rejects mismatches even when the transaction list is empty; stale binaries cannot silently supply old empty-block rules.

## Native process boundary and exact work backend

The native application bridge drains stdin/stdout/stderr concurrently and enforces16MiB
input,32MiB stdout,64KiB stderr and a30-second deadline. Overflow/timeout terminates and
reaps only its owned process session. A selected native backend never falls back to the
Python oracle. Request/response contexts and the resulting state root remain checked.

`TRNM_NATIVE_WORK` additionally selects the fixed-size native work bridge in M01. Proof
bytes and decoded products are compared against the separate oracle. Unknown or failed
native executables reject. This joins native work and application components to the
existing reference ledger; it is not a new standalone native consensus/persistence host.

## Exact continuation counterexamples and cost comparison

`test_block_scoped_workers_and_no_duplicate_main_signature_on_conflict` asserts both
the resource count and exact roots. `test_funding_dependency_replays_state_not_main_signature`
uses a preceding transfer that makes a later sender solvent. `test_capacity_prefix_commands_do_not_speculate_unbounded_snapshots`
checks the shared deadline capacity, including the rejecting next reservation.
`test_later_invalid_signature_does_not_change_canonical_error` preserves error ordering;
`test_single_signature_context_cannot_be_reused_for_another_payload` changes signed bytes.

`experiments/executor_comparison.py` interleaves unchanged baseline and new binaries on
identical signed inputs, against the separate Python result. It records source and binary
hashes, request hashes, roots, receipt digests, process-inclusive and executor-only times,
RSS and missing VRAM/inclusion/confirmation fields. Regressions remain in the report; no
speedup threshold can mask a wrong result. Old `evidence/pon-v3` costs remain bound to their
measured source and are not relabelled as this continuation's performance.
