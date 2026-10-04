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

### Sharing complete bytes within a warm parent binding

`CheckedExecutionParent::bind` visits every actual State entry in key order, applies
the original canonical JSON rules to every value, and compares every key/value with
the optional opaque predecessor. A detected byte or key-count mismatch does not skip
later canonical validation. Canonical errors still precede protocol `LIMIT`, which
precedes `COMMITMENT_PARENT`, which precedes `COMMITMENT_ROOT`; invalid cache ceilings
are rejected before binding work as before. Exact 65,536 keys, 160-byte keys and
4,096-byte canonical values retain their inclusive bounds.

Only after complete equality and the expected-root comparison does the warm binding
share the predecessor's immutable canonical-map Arc. It retains the same immutable
borrow of the actual State. It creates no second complete canonical map and copies no
State keys for that binding; it still serializes every actual value, with at most one
newly serialized value live in the comparison. This remains O(N) work and is not an
allocator, RSS, CPU deadline or faster-state-read claim. A cold binding still creates
the complete canonical map and computes the original full root. Successor encoding,
full differences, checked tree application, budget fallback and durable publication
are unchanged. Conservative workspace charges remain unchanged even when this one
operation shares its parent map.

The in-module `warm_parent_binding_*` controls check actual Arc identity alongside
complete canonical bytes, State/root/receipt/delta parity with the original executor
and a separately copying warm-binding control. They also check changed actual keys
and values, late canonical failures, exact limits, wrong roots, cancelled staged roots
and successful retry. The existing corrupt-tree fallback remains required. The ignored
The copying control mirrors the earlier algorithm but uses the current parent type,
including one additional `Arc::new` wrapper allocation; it is not an old binary. The
`warm_parent_binding_component_timing` control alternates eight copying/sharing sample
pairs at three State sizes, with 16 complete binds and drops per sample. Its logical
additional retained-map counts exclude per-value serialization temporaries; they are
not allocator measurements. Root/execution parity and snapshot seeding occur outside
the binding clocks. The observation does not replace Node actual-KV, stale-generation,
cancelled-publication or reorganization tests.

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
| A retained predecessor would require more than 65,536 complete changes for `StateTree::apply` | `FullRoot(DeltaBudget)`, `snapshot=None` | Compute the complete root before cloning the required full delta. Removals plus insertions can exceed this batch limit while both complete states remain valid. |
| Internal tree application cannot reproduce the checked predecessor | `FullRoot(InternalSnapshotMismatch)`, `snapshot=None` | Use the complete root result and retain the expected-root comparison; never repair actual KV from the cache. |
| Actual state root differs from expected root | `COMMITMENT_ROOT` | Reject the state through the owner's existing root-error boundary. A cache miss is not permission to accept corrupted state. |
| `execute_checked` receives a predecessor with different complete canonical bytes | `COMMITMENT_PARENT` | An internal caller must discard/reseed an unrelated cache before execution; a wrong cache context must not become a new consensus verdict against an otherwise valid block. |
| Invalid canonical bytes or protocol state bounds | Existing canonical/`LIMIT` error | Preserve validation and error ordering at the owner's established boundary. |
| Invalid cache ceilings or arithmetic overflow | `COMMITMENT_CACHE_LIMIT` / `COMMITMENT_CHARGE` | Fail the internal computation/configuration; do not publish a staged result. |

`CommitmentObservation` reports method, actual keys/payload bytes, changed keys,
logical changed payload bytes, compressed nodes when available and workspace charge.
`changed_payload_bytes` sums each changed key and its present canonical before/after
values. It is not Vec capacity, allocated bytes or RSS. These counters are computation
observations. They are neither throughput measurements nor certificates of public
availability, model contribution, useful-task demand or proof-cost hardness.

### Allocation order and independent limits

The adapter still completely canonicalizes actual state before selecting an optional
cache method. This preserves late canonical errors before protocol `LIMIT` and preserves
the owner's complete actual-state/root checks. It cannot turn the 8 MiB or 512 MiB
software policies into a limit on initial JSON State or canonical-map allocation.

After encoding, an ordered merge of the two actual canonical maps counts every changed,
new and deleted key and its logical before/after bytes using checked arithmetic. The
planning pass borrows entries: it allocates neither a union `BTreeSet` nor a `Change`
payload. Key/payload/workspace selection occurs before tree construction or complete
public change cloning. If resource selection chooses `FullRoot`, the complete
`state_root` call finishes and its temporary root work is released before allocating
the required returned `Vec<Change>`. The cached path allocates that exact-count vector
after budget selection and then performs checked tree application. Delta content and
key order are unchanged; a fallback never drops changes. An internal tree-application
failure is discovered after its necessary changes exist and still performs the original
complete-root fallback. This ordering improvement does not bound that path's RSS.

For `N` entries, let `C` be the sum of the **actual** canonical key/value Vec capacities,
`P` the sum of their byte lengths, and `D` the count of complete old/new differences.
The existing software formulas are:

```
map   = C + 1024*N
tree  = C + 256*max(2*N-1,0) + 257*32
workspace = 3*(max(old.map,new.map) + max(old.tree,new.tree))
            + 2*max(old.P,new.P) + 256*D
```

No length-only estimate replaces `C`. The default thresholds are inclusive: an exact
limit remains eligible; one byte above a selected payload/workspace limit selects the
full root. Key, payload and workspace reasons retain that order when several limits
are exceeded. With a retained predecessor, `D > 65536` then selects `DeltaBudget`
before any delta/tree allocation. Without one, tree rebuilding has no apply-batch
limit. This known capacity case is distinct from an unexpected internal snapshot
application failure. `D` may include removed and newly introduced keys, not just writes in a
transaction. The complete root and returned delta remain mandatory even on fallback.

For the currently inspected Rust 1.95.0 implementation (commit
[`59807616e`](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/raw_vec/mod.rs#L463))
and locked serde_json 1.0.149, serialization starts with capacity 128 and only appends;
Vec growth records `max(2*capacity, required)`. Key `to_vec` copies have the requested
length capacity. In this **implementation-specific domain**, `C <= 2*P + 128*N`.
If both actual states have at most 65,536 keys and at most 8 MiB payload, even disjoint
key sets have `D <= 131072`; substituting these bounds gives workspace at most
503,340,384 bytes, below 512 MiB. Thus the default workspace guard is redundant in
that domain. This is not a protocol or stable allocator/API guarantee; the adapter
still uses actual capacities and retains the guard. An execution parent beyond
the cache payload limit, another runtime's allocation behavior or lower selected
limits is outside that argument. It does not bound physical allocation or RSS.

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
The complete actual-state encoding and borrowed difference count occur before the
optional cache budget decision; complete change cloning follows it. The 512 MiB
software charge therefore does not establish a hard allocation limit or bound the
complete-root fallback's physical resource consumption.

## Required evidence

The [actual M06 controls](../../../../trillionnium/crates/trnm-mvcc-fee/tests/pon_commitment.rs)
compare complete State, root, ordered receipts, execution metrics and reversible changes
against the original executor. They include signed transaction prefixes, different worker
counts, sequential successors/reward maturity, late invalid signatures/nonces/funds,
changed actual state with unchanged context, removals/empty values, wrong roots and cache
parents, branch staging and cache/protocol capacity boundaries. Internal cache damage
must fall back to complete computation while still rejecting an incorrect actual root.

The resource controls also compare exact 65,536 keys combined with exactly 8 MiB
canonical payload, payload minus/plus one byte, and the unchanged 65,537-key `LIMIT`.
They use complete original roots, test complete returned deltas and preserve late bad
canonical/error precedence. Workspace controls measure a real software charge `Q`
from actual canonical Vec capacities and select local limits `Q-1`, `Q`, `Q+1`.
They prove the inclusive **selected** threshold; they do not pretend `Q` is 512 MiB.
Test-only markers bracket real change-buffer construction and root computation to
check the prior/new allocation order. They do not count allocator bytes and are absent
from production observations.

The finite [component example](../../../../trillionnium/crates/trnm-mvcc-fee/examples/pon_commitment_resource_bounds.rs)
emits exact shape/charge/method/elapsed records and compares every result with the
original full root. It also exercises disjoint 65,536-key states, each exactly 8 MiB,
including values just above serializer capacity 128. Their 131,072 complete changes
select `DeltaBudget` before allocation and retain the complete returned delta and
original full root. Exact 65,536 and 65,537 differences also test this selector and
complete old/new delta parity. Its `kXXXXX`
and disjoint-prefix rows exercise the generic canonical-State
space; installed commands provide typed account/task/evaluation records rather than
an arbitrary key/value writer. The example is not evidence that native transactions
can reach all of those shapes from an installed genesis. Existing signed-prefix tests
continue to check real M06 command rules. A native reachable payload/workspace case
must separately identify its command/profile, funded/authorized initial state, complete
transaction sequence, mandatory cleanup and full original state/receipt checks.
Current tag1 growth alone, even at 65,536 keys, does not grant payload/workspace
combination or maximum-state real-time capacity acceptance.

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
