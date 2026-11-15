# Reorganization post-write readback review — 2026-11-01

**Status: source review only; not implemented, built, measured or accepted.**

Reviewed source: [`bb84d3ded8acc8b33ddbf32e1c8defae76900a0e`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/bb84d3ded8acc8b33ddbf32e1c8defae76900a0e/trillionnium/crates/trnm-pon-node/src/store.rs). This note records a bounded possible follow-up to the measured account-graph cost. It is an audit/design note, not a replacement development plan or a claim that the original four-second business gate will pass.

## Existing admission scope cannot simply move earlier

The actual order is:

1. `check_admission_parent -> state_at_with_progress` checks the actual parent State and graph **before** `BEGIN IMMEDIATE`.
2. `persist_admission_execution` opens its existing WRITE transaction and captures `original_readback_owner`.
3. The operation writes blocks, ancestry, deltas and snapshots.
4. `publish_with_readback` checks the parent graph.
5. `native_store::apply` writes account nodes; `save` writes the child record.
6. Only after those writes does the operation establish `PostWriteReadback`.
7. That scope already reaches the subsequent child, genesis, parent, active and precommit checks.

The first parent check has no existing WRITE transaction. The second parent check is separated from the current scope by legitimate account/record writes. Moving the scope earlier would invalidate its write epoch. Ignoring that change or issuing a new stamp without a new complete graph verification would violate the safety boundary. The observed 69 graph calls therefore are not 69 checks of one interchangeable snapshot.

## Bounded extension: existing reorganization transactions after their last writes

`atomic_with_progress` currently runs the operation inside `BEGIN IMMEDIATE`, then checks active state before commit, executes the original continuous/mining checkpoint and final progress callback, and commits. Reorganization closures already end with a persisted-state check; their atomic tail then checks active and genesis graphs without the same readback scope.

| Existing transaction | Point after its final actual write | First full graph verification | Possible same-transaction reuse |
| --- | --- | --- | --- |
| Reorganization intent | After reorg/lifecycle inserts and the existing row/step checks | Existing persisted-state check of old state and staged slot | Atomic active check; also genesis when old active is genesis |
| Each detach/attach step | After delta application and cursor update, then existing reorg-row checks | Existing persisted-state check of the resulting state and staged slot | Only an identical Record encountered again by atomic active/history checks |
| Final publication | After active/events/reorg/lifecycle writes and old-slot deletion, then existing row/event checks | Existing persisted-state check of the target and final slot | Atomic active check of the same target |

This extension must keep the existing transaction boundaries. A scope must be discarded at every transaction end and never passed into the next reorganization step.

### Required helper shape

1. Capture the original transaction identity immediately after the existing `BEGIN IMMEDIATE`, before any callback or write.
2. Execute all existing actual writes and existing row/event checks.
3. At the explicit final-write boundary above, create the existing bounded `PostWriteReadback` with the original schema, context, connection and transaction checks.
4. Pass it through the existing persisted-state verification so the first relevant graph is fully verified.
5. Return the same scope to the atomic tail and use the existing active-before-commit readback form.
6. Retain the original continuous/mining checkpoint and the final progress callback.
7. **After that final callback and before the original COMMIT**, require that the post-write scope's write epoch is still unchanged.
8. Preserve original transaction-identity checks on success and failure. If no valid scope exists, perform the original full verification path.

Use the existing bounded named slots and actual Record equality. Do not introduce an arbitrary historical-block verdict cache. Equal account-root bytes alone do not authorize reuse; current complete State/Record/root checks must precede any graph hit.

### Existing invalidation API detail

`validate_consumed` calls `current()` but ignores its boolean return. The current API rejects writes after an already-consumed hit; a write before any consumed hit can instead disable reuse and force full work. That existing behavior must not be misdescribed as the proposed strict no-further-write tail fence.

The proposed helper needs a strict final check that rejects `current() == false` as a post-write change, including when no hit has yet been consumed. A suggested internal method such as `require_unchanged_after_last_write` is **not implemented**. It must not clear, re-stamp or re-enable an invalidated scope. The proposed tail has no legitimate SQL writes left, so rejecting any additional write is appropriate.

## Source-derived savings, not measured speed

For an import of N blocks from genesis, followed by one activation through the existing N-step reorganization:

| Phase | Current graph traversals | With the proposed scope | Traversals saved |
| --- | --- | --- | --- |
| Intent | 3 | 1 | 2 |
| Each attach step | 3 | 2 | 1 per step |
| Final publication | 3 | 2 | 1 |
| Total | `3N + 6` | `2N + 3` | **`N + 3`** |

For N=7, this particular tail is 27 -> 17: ten fewer traversals. Only if the executed path has this shape and every other call remains unchanged could an overall observed count of 69 become approximately 59. This is a source call-count derivation, **not** an actual run or a CPU/latency guarantee.

If old active is not genesis, the resulting state, old active and genesis often are three distinct Records: each step usually saves nothing, while intent and final publication can each save one traversal. Ordinary fast single-block extension usually checks distinct target and genesis graphs, so this proposal does not automatically remove either check.

## Counterexamples and acceptance obligations for a later implementation

These are required behavioral negatives, not tests that merely assert a larger cache-hit counter:

1. **Current inputs remain authoritative.** After the first full graph, change supplied State, actual Record, root, delta or active slot. A later hit must not bypass `complete(settings, current State)` or any original refusal.
2. **Every real write invalidates the new tail scope.** Inject graph-node corruption, Record modification, a no-row UPDATE, failed write, DDL-and-restore, or a write followed by rollback between first verification, reuse and the final callback. The proposed strict tail must reject; it must never re-enable the scope.
3. **Connection and transaction identity remain fixed.** Preserve rejection of COMMIT/BEGIN ABA, ROLLBACK/BEGIN, unexpected SAVEPOINT controls and connection replacement.
4. **Schema/VM fences remain.** Preserve current refusal or full-work fallback for temp triggers/tables, attached databases, `writable_schema`, and prepare-only RESET/rootpage operations. Equal catalog text is not proof that an old prepared VM remains valid.
5. **Every retained full traversal keeps every original callback.** Do not remove graph-node `progress()` calls or change cancellation, CPU or Host error identity. A legitimately skipped duplicate graph does not fabricate callbacks it did not perform.
6. **The final fence must follow the last callback.** A callback after the final scope check could otherwise mutate data before COMMIT. Verify the strict epoch condition after the original final progress callback.
7. **Original recovery semantics remain.** Retain every intent, detach/attach, before-publication and published crash cut, rollback and reopen check, event ordering and final State equality. No scope survives a transaction boundary.
8. **Differential evidence is required.** Compare scope disabled/enabled using the same packets, initial database and original budgets. Compare all resulting ledger facts and separately count actual full graph traversals and their callbacks.

## Decision

The safe potential optimization is confined to duplicate verification in the read-only tail of an existing reorganization WRITE transaction. The current admission scope cannot safely be moved across intervening account writes. No implementation or performance result is delivered by this review; the remaining original business and long-History gates remain open.
