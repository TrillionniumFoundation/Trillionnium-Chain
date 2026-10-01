# Checked derived state commitments

This contract covers the pure M06 commitment adapter in
[`pon_commitment.rs`](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_commitment.rs).
It accelerates computation of the existing state root. It does not change state bytes,
signed domains, consensus rules, database schemas, transaction execution or ownership.
M15's native Node remains the durable owner; M05 retains admission and pool lifecycle.
The in-memory adapter is not an additional ledger, snapshot store or task scheduler.

## Inputs and results

`State` is the existing complete ordered map from string keys to JSON values. Every
adapter call canonicalizes all actual entries and applies the existing protocol limits.
`Hash` is the existing 32-byte state-root type. A `CheckedCommitment` has private fields:
the canonical key/value map, a structurally shared `StateTree`, its root and accounting.
Cloning shares immutable Arcs; it does not authenticate a new state or retain a history
on behalf of the caller.

| Operation | Required input | Result and authority |
|---|---|---|
| `checked_snapshot` | Complete actual State, owner-selected expected root, optional prior derived snapshot, cache limits | `PreparedCommitment`; computes the root from actual bytes and rejects a mismatch with the expected root. A prior snapshot only accelerates the complete key/value difference. |
| `execute_checked` | Complete actual parent, its expected root, matching optional predecessor, `ExecutionRequest`, existing `Config`, limits | `StagedOutput`; runs the existing complete execution rules and returns State, ordered receipts, metrics and a derived successor. It neither commits nor advances the predecessor. |
| `derive_snapshot` | Complete actual successor State, optional prior staged snapshot, limits | Pure `PreparedCommitment` computation where a miner has not yet constructed its header. It does not check a supplied expected root: admission must still compare the header and committed-state reads must use `checked_snapshot`. |
| `PreparedCommitment` | Produced by computation | Root, optional retained snapshot, canonical changes and `CommitmentObservation`. Changes come from comparing full actual states; they are not trusted database deltas or a caller's claimed write set. |

`ExecutionRequest` preserves the existing transaction bytes/order, height, miner,
parent ID and worker count. A matching snapshot must contain the complete canonical
parent bytes and its expected root. The adapter does not cache execution results,
signatures, fee decisions, nonce checks, conflicts or partially accepted prefixes.
Serial and parallel execution retain the existing canonical replay and receipt order.

## Resource selection and errors

The default retained-cache limits are 65,536 keys and 8 MiB of canonical key/value
payload. The workspace software-charge ceiling is 512 MiB. Operators may select lower
adapter limits; they cannot use this API to increase those ceilings. Charges include
canonical maps, compressed tree nodes and staged changes with checked arithmetic.
They are conservative software accounting, not a measurement or physical bound on
process RSS, allocator overhead, parsed JSON State, SQLite, proof buffers or archives.
Callers must bound retained snapshot versions; an unbounded collection of Arc clones
would violate this contract even if every individual snapshot fits.

Cache limits select the computation method. They do not reduce the protocol's existing
65,536-key, 160-byte-key and 4,096-byte-value limits. A valid state beyond a selected cache limit
uses the complete root computation, retains no oversized snapshot and reports the
reason. The fallback still performs actual canonicalization and protocol validation.
With the default key ceiling equal to the protocol ceiling, a 65,537-key state is
rejected with `LIMIT`; it is not a cache fallback. Historical 8,192- and 16,384-key
local policies remain selectable and retain their full-root fallback behavior.
The larger software ceiling permits retaining a checked tree at the protocol key
ceiling when the payload and actual workspace charges fit. It does not qualify
maximum-state throughput, an allocator/RSS bound, or any public service guarantee.

| Condition | Adapter result | Caller requirement |
|---|---|---|
| Cache key, payload or workspace charge exceeds its limit | `FullRoot(KeyBudget/PayloadBudget/WorkspaceBudget)`, `snapshot=None` | Continue existing valid-state execution; do not reject a block because this optional cache cannot retain it. |
| Internal tree application cannot reproduce the checked predecessor | `FullRoot(InternalSnapshotMismatch)`, `snapshot=None` | Use the complete root result and retain the expected-root comparison; never repair actual KV from the cache. |
| Actual state root differs from expected root | `COMMITMENT_ROOT` | Reject the state through the owner's existing root-error boundary. A cache miss is not permission to accept corrupted state. |
| `execute_checked` receives a predecessor with different complete canonical bytes | `COMMITMENT_PARENT` | An internal caller must discard/reseed an unrelated cache before execution; a wrong cache context must not become a new consensus verdict against an otherwise valid block. |
| Invalid canonical bytes or protocol state bounds | Existing canonical/`LIMIT` error | Preserve validation and error ordering at the owner's established boundary. |
| Invalid cache ceilings or arithmetic overflow | `COMMITMENT_CACHE_LIMIT` / `COMMITMENT_CHARGE` | Fail the internal computation/configuration; do not publish a staged result. |

`CommitmentObservation` reports method, actual keys/payload bytes, changed keys,
compressed nodes when available and workspace charge. These counters are computation
observations. They are neither throughput measurements nor certificates of public
availability, model contribution, useful-task demand or proof-cost hardness.

## Durable-owner integration requirements

The Node must read the complete actual KV and canonical bytes before checking a cached
root. A cache keyed by a block, generation or slot cannot substitute its old State for
the database merely because those identifiers still match. Actual changed, deleted and
new keys must be included in the full difference. The resulting root must match the
existing committed block record.

A transaction-pool preview executes every complete candidate prefix with the actual
parent and original miner/configuration. Neither a successful preview nor an abandoned
mining attempt publishes its speculative successor as the durable cache. Task-output
accounting retains all eligibility/material/window/product checks: when it changes no
state, the caller can reuse this execution's completed root; when it writes state, the
caller must derive the new root from the complete resulting state. A Maintenance task
does not excuse execution of signed transactions such as atomic renewal.

Admission checks the complete proof, header state root and ordered receipts before its
database transaction. Direct activation checks the full actual KV after applying the
delta. A retained committed snapshot may be published only after the relevant SQLite
COMMIT succeeds and its exact block/root context is established. SQL errors, aborted
transactions, invalid roots and failure hooks cannot advance that cache.

Forks, inactive admitted extensions, reopening, recovery and interrupted reorganization
must explicitly discard/reseed unrelated derived context or use complete computation.
Historical reconstruction still checks every actual delta's before bytes and every
intermediate block root. It may carry one temporary derived tree while reconstructing;
it must not trust an old cached State or accumulate an unbounded root history. Existing
operator-removal and revocation records retain their independent nonrewind semantics.

The native implementation is in
[`store.rs`](../../../../trillionnium/crates/trnm-pon-node/src/store.rs) and
[`store/mempool.rs`](../../../../trillionnium/crates/trnm-pon-node/src/store/mempool.rs).
`read_active` checks complete actual slot values and publishes only that committed
context. `execute_derived` validates an admitted parent's expected root before running
M06; pool previews keep their existing admission gate and complete-prefix execution.
`state_at` carries one temporary tree from a checked historical snapshot and checks
each actual delta application. Mining derives a successor for its header; admission
independently executes and compares that header's root and ordered receipts. Direct
activation stages inside the existing SQLite transaction and publishes the cache
after successful COMMIT. Reorganization and recovery invalidate it. There is one
optional retained active cache, not a cache per admitted block or pending prefix.

`derived_commitment_status` reports optional cached root/key count/software charge
and the last calculation observation. A last observation can describe an abandoned
preview; it is not evidence that its state was activated or its transaction confirmed.
The complete actual-state encoding and differences occur before the optional cache
budget decision. The 512 MiB software charge therefore does not establish a hard
allocation limit or bound the complete-root fallback's physical resource consumption.

## Required evidence

The [actual M06 controls](../../../../trillionnium/crates/trnm-mvcc-fee/tests/pon_commitment.rs)
compare complete State, root, ordered receipts, execution metrics and reversible changes
against the original executor. They include signed transaction prefixes, different worker
counts, sequential successors/reward maturity, late invalid signatures/nonces/funds,
changed actual state with unchanged context, removals/empty values, wrong roots and cache
parents, branch staging and cache/protocol capacity boundaries. Internal cache damage
must fall back to complete computation while still rejecting an incorrect actual root.

Node integration additionally needs actual packets, pool pre/post validation, first and
repeated task outputs, signed atomic renewal, fork/reorganization, reopen, same-context
database mutation and SQL/fault rollback controls. Exact committed source and binary
bindings are required for a new measurement. Component parity does not qualify Node
integration or establish an end-to-end improvement. A failed or lagging network case
retains its incomplete transaction, confirmation and inactive-branch counts.

The actual Node controls in
[`derived_commitment.rs`](../../../../trillionnium/crates/trnm-pon-node/tests/derived_commitment.rs)
compare nine inactive extensions with complete executor State/root/receipts and exact
stored deltas; mutate, add and corrupt actual KV bytes under an unchanged active tip;
reject a correctly proven packet with a wrong state root; inject SQLite admission and
activation failures; interrupt a heavier-fork switch and reopen; and execute 8,192
distinct signed transfers while retaining a checked snapshot above the previous
8,192-key software limit. M06 controls separately retain explicit lower-limit,
16,385-key, payload and workspace full-root fallback coverage. Their oracle
rebuilds configuration from installed constants and the specified development settings,
then separately checks packet network/parameters. Existing task-output parity,
signed-task lifecycle, pool and native fault/recovery controls remain required.

Use the existing [performance acceptance](PERFORMANCE_ACCEPTANCE.md) to measure the
new backend under the same state growth, load, confirmation policy and finite budgets.
Root, full-state encoding, prefix execution, persistence, propagation and client-confirmed
completion remain distinct costs. The cache cannot expand the nominal block budget,
weaken probabilistic confirmation or turn Tailnet simulation into independent WAN proof.
