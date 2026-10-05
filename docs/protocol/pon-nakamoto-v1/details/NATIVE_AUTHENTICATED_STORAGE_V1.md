# Explicit native authenticated storage V1

## Status and scope

`Node::open_with_authenticated_state` selects a fresh local storage namespace.
It installs persistent account nodes and authenticated state records in the
**same `native.sqlite` database and the same native write transaction** as the
actual admitted block and its canonical deltas. No `AccountArchive` or
`AuthenticatedStateArchive` connection is opened by this backend.

The existing consensus profile, header state root, transaction signatures,
work/ticket relation, difficulty and required-work fork choice retain their
meaning. This is a local storage selection, not a new consensus revision or a
partial-State executor. The complete `State`, complete non-account partition and
independent full root construction remain required. The installed 65,536 total
state-key capacity does not change. Public service, work hardness and production
qualification remain separate acceptance obligations.

Source ownership is the native Node in
[`store.rs`](../../../../trillionnium/crates/trnm-pon-node/src/store.rs), its
[`native_authenticated` transaction component](../../../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs),
and the reused Patricia node implementation through
[`native_store`](../../../../trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs).
The earlier [account archive](ACCOUNT_ARCHIVE_PROTOTYPE_V1.md) and
[authenticated archive](AUTHENTICATED_STATE_ARCHIVE_V1.md) keep their independent
research namespaces; their publication APIs do not authorize native writes.

## Selection and durable identities

| Entry or identity | Meaning |
| --- | --- |
| `Node::open` and existing owner openers | Existing branch backend; its DDL and `native-branch-schema-v2` domain retain their exact bytes. |
| `Node::open_with_authenticated_state` | Explicit integrated authenticated backend. An existing legacy database is rejected rather than converted during open. |
| `Node::open_with_authenticated_state_and_fault` | The same explicit backend with the existing initialization fault hooks. |
| `native-authenticated-branch-schema-v1` | Hash domain for the exact legacy DDL plus the two integrated tables. |
| `pon-native-authenticated-state-record-v1` | Strict canonical stored record, with a separately hashed record identity. |
| `Node::authenticated_account_multiproof` | Read a compact account query from the actual integrated tree in one SQLite read snapshot. |
| `Node::migrate_to_authenticated_state` | Explicit checked legacy source to fresh destination migration; detailed below. |

The existing native CLI exposes `--state-backend authenticated-v1` through its
ordinary Node-opening helper, including local status, mining, sync and service
commands. Omitting the flag, or selecting `--state-backend legacy-v2`, preserves
the existing default backend. An authenticated selection combined with an
external task/mining/continuous-owner journal is explicitly refused until that
ownership combination has its own opener. Migration remains a separate API on
the already held source Node; an ordinary CLI open must not silently recover or
convert a source before an intended migration snapshot.

The additional tables are:

```sql
CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);
CREATE TABLE native_state_commitments(block BLOB PRIMARY KEY,data BLOB NOT NULL);
```

`archive_nodes` uses the existing content-addressed Patricia node bytes and hash
domains. A leaf retains the owner, balance and nonce. Compressed forks retain
their depth, representative path, child identities and child hashes. Each child
is checked for its actual encoded identity, depth, path and lifted hash before
use. The native schema selects these rows; there is no inference from an archive
database file or from a caller's serialized checkpoint.

Each `native_state_commitments` row binds its native block and parent, the parent
record identity, height, complete packet digest, canonical delta count/root,
complete authenticated `StateCommitment`, and persistent account root node,
digest, count and balance. The complete commitment binds the existing state root,
account root/count/balance, complete non-account root/count, escrow, rewards and
issued funds. Strict decoding rejects unknown fields, noncanonical bytes,
incorrect identities and inconsistent account projections.

The default opener rejects the additional schema. The authenticated opener
rejects the old schema. Both reject a pending migration marker, including a
symbolic link at that marker name. No opener removes that marker to conceal a
failed migration. Existing protected owner markers remain mandatory; the new
plain opener cannot bypass a task, mining or continuous-owner requirement.

## Actual block admission and incremental account persistence

Admission first performs the existing full native work and application checks.
It also records qualified task output after M06 when the selected task requires
that operation. The final `output.state`, including that product record, is the
source of the new authenticated commitment. The pre-product M06 state cannot
stand in for the final header state.

The existing immediate SQLite transaction then writes the actual block,
ancestry index, canonical deltas and any scheduled full snapshot. In the new
backend that same transaction performs the following additional work:

1. Read and verify the retained parent commitment, actual complete parent state
   and required account nodes.
2. Read the actual ordered `deltas` rows and compare them with the exact native
   before/after state difference. A omitted row cannot be hidden by a full
   snapshot of the child.
3. For each changed account, authenticate its old leaf against the original
   parent root and retain its existence and nonce. Sort all changes by hash path,
   merge their compressed subtrees and save each final changed path once. A missing child node is a data error, not an absent account.
4. Derive account count and balance from those changes. A wide signed
   accumulator prevents a credit-before-debit key order from overflowing a
   valid final `u64` total. Account deletion or decreasing nonce is rejected.
5. Independently rebuild the complete final state's account/non-account roots
   and funds. Compare those results with the incrementally persisted account
   root, count and balance.
6. Write the authenticated record, then read the actual stored nodes, record,
   required delta history and genesis anchor before commit.

Genesis alone seeds the complete initial account tree. Later blocks reuse
unchanged nodes and retain prior versions for inactive branches. Neither the
reference calculation nor the stored record alone is accepted in place of the
other. The complete record is created from the actual Node execution, not from
a deserialized observation supplied by an archive caller.

Block, ancestry, delta, snapshot and authenticated-record writes check their affected
row counts. Content-addressed duplicate node writes also compare existing actual
bytes. Before COMMIT, both backends reread the exact deltas and packet, reconstruct
the stored parent and child states, and check the active state. The newly inserted
ancestry row set must exactly match its private operation-local expected rows after
all subsequent writes; each row and its visible halves remain checked. A cancelled or
failed transaction retains no subset of its new block, account paths or record.
The final cancellation fence precedes commit; there is no later cancellation
that retroactively changes a committed block into failure.

## Reads, selection, reorganization and recovery

`read_active` reads actual KV bytes and checks the installed header root as
before. With the new backend, it also checks the complete authenticated
commitment and traverses every required account node, comparing the real leaves,
count and balance with the complete state. `state_at` keeps the existing
snapshot/delta reconstruction, with the same authenticated comparison at every
reconstructed state. A missing record or node has no ordinary-KV fallback.

Non-genesis full snapshots remain declared optional accelerators under the
existing retention rule. Canonical deltas and the genesis snapshot remain the
reconstruction anchors. The integrated history check seals every required
delta record and parent relation back to genesis. Account nodes needed for an
individual state are checked when that state is read; this does not constitute
a perpetual audit of every inactive branch's physical storage.

There is one native `active` selection and one existing reorganization journal.
The backend does not introduce a second active account pointer that would need
a separate cross-database commit. Required-work selection retains its original
policy, including rejection of a lower-work requested target.

The native commit boundary also fixes concrete faults in the old backend,
without changing its schema. After the final event write, activation now checks
the expected tip, generation, slot, actual state root and exact event rows
**before** COMMIT. Reorganization staging checks the actual post-step state and
cursor, and final publication checks the active selection, events, completed
journal row and state after all writes and trigger effects. A suppressed delta,
an event trigger deleting KV, or an event trigger rewinding the active pointer
causes rollback instead of a successful unreadable head or a post-commit error.
The final active-tip ancestry levels, seals, visible half links and exact row count
are checked in that same commit fence. A late event that deletes jump rows or adds
a spurious level therefore cannot publish a successful unreadable selection.

Reorganization remains resumable through its original several transactions.
Failure during its final publication preserves the already committed pending
intent and checked cursor; it does not pretend that the whole reorganization
was one transaction. After the failing condition is removed, ordinary recovery
resumes that intent. Local replay, outbox, pool, owner facts and monotone event
generations are not restored from a branch snapshot.

## Compact proofs from the installed native tree

`authenticated_account_multiproof(block, owners)` accepts an actual retained
native block locator and the requested owners. It reads that state in one
SQLite snapshot, verifies its stored commitment and nodes, and constructs an
opaque account-query checkpoint from the actual retained root. It then derives
AAM1 bytes directly from those `archive_nodes` rows.

The returned tuple contains the opaque checkpoint, untrusted serialized
`Multiproof`, and construction observation. `CheckedMultiproof::verify` still
checks the proof before its account values can gate execution. Its checkpoint
is a binding for this native point query; it makes no assertion that a separate
AccountArchive checkpoint or archive ancestry was persisted. A caller cannot
replace the node root or account values through a report argument. The API
requires the explicit authenticated backend and has no silent legacy fallback.

`authenticated_account_multiproof_with_progress` preserves that relation while
exposing cancellation before the read snapshot, throughout historical State replay
and retained-node verification, during actual trie reads and proof hashing, and
before output. The original method delegates with a no-op callback. Oversized
requests (more than66,049 owners) and duplicate owners reject before opening a
transaction or reading State; the explicit-backend refusal retains precedence.
The existing `NATIVE_ACCOUNT_PROOF:Budget` and `InvalidWitness` diagnostics remain.
Cancellation returns the caller's original typed error and drops the read
transaction without returning a partial proof. A missing/corrupt actual node still
carries local-integrity provenance. Individual commitment and canonical-JSON
primitives remain bounded single stages; these callbacks do not preempt each hash.

This query already shares the actual native state source with compact proof
construction. It still performs a full-state verification before serving the
query. It therefore establishes source binding and format interoperability,
not a measured constant-cost proof service.

## Explicit migration into a fresh destination

[`authenticated_migration`](../../../../trillionnium/crates/trnm-pon-node/src/store/authenticated_migration.rs)
provides `migrate_to_authenticated_state` and its cooperative-progress variant.
The caller supplies an already open legacy Node and a **new destination
directory**. Existing destinations are refused. The source owner lock and an
immediate SQLite transaction fence the source snapshot; migration does not
admit, activate, acknowledge, recover or mutate anything in the source.
The destination's canonical parent must be outside the source directory, including
when a symbolic-link alias points back into the source.

Migration checks the exact source schema, metadata, integrity, local history,
replay, outbox and pool. It independently revalidates retained blocks, work,
ordered execution, task output, exact deltas, snapshots and ancestry. It copies
every legacy table, including local events, replay/outbox, pool and
`sqlite_sequence`, into the new schema. It builds the authenticated nodes and
records from those actual replayed states in the destination's transaction.
The only permitted difference in the copied cells is the explicit schema
metadata value. A typed, ordered digest and direct row comparison verify each
preserved table.

An existing pending reorganization is verified and copied as pending; migration
does not complete it in the source. A later explicit destination open may resume
it through ordinary checked recovery. Migration itself preserves the source
tip, generation, cursor and irreversible facts exactly.

Publication has two distinct filesystem boundaries:

1. Create a private `native-authenticated-migration-staging-*` sibling, write and
   synchronize `authenticated-migration.pending`, then synchronize the staging
   and parent directories. The requested destination does not exist yet.
   Safe `rustix::fs::renameat_with(..., RenameFlags::NOREPLACE)` atomically makes
   that already fenced directory visible at the destination. An existing or
   concurrently created destination is never replaced. The explicit migration
   implementation currently requires Linux; an unsupported or failed atomic
   rename returns an error without falling back to an overwriting rename.
2. In the fenced destination, commit the complete copy and authenticated records,
   close the writer, and open a new SQLite connection to verify actual committed
   disk bytes. Under its immediate transaction, directly compare every preserved
   row and both derived tables, write and synchronize `authenticated-migration.json`,
   and synchronize the database and directory. After the **last** caller progress
   callback, repeat schema/integrity, exact row and derived-table checks without
   calling user code again. Check raw database/WAL/journal/owner fingerprints,
   inode identities, exact file names, and marker/receipt bytes. Close the clean
   connection, then remove the pending marker and synchronize the directory.

Raw file checks prevent a same-inode file change from being hidden by SQLite's
cached pages. The source's durable database, WAL and owner payloads are checked
unchanged as well; SQLite shared-memory lock/read marks are coordination state,
not migrated irreversible facts. No source checkpoint, recovery or acknowledgement
is executed. These checks do not authorize bypassing the filesystem or writer
locks after the operation has completed.

Failure or cancellation after staging creation but before destination visibility
retains that private staging directory. The operation has not created the target;
an independently existing or racing target is left intact. A later failure retains
the target's pending marker, so both ordinary and authenticated openers refuse it. A retry
uses another fresh destination and never silently removes the marker or resumes
an unverified partial copy. If interruption happens after final publication, the
already fully checked target may exist without a returned receipt; that does not
turn an incomplete copy into success. The saved receipt is evidence of this local
copy, and grants no production activation or permission to delete the source.

Migration refuses external task, mining and continuous-owner configurations.
Their separate protected journals would require an explicit ownership migration
relation; copying a database must not downgrade their required owner mode.

## Native tests and independent observation

The test source is
[`native_authenticated_tests.rs`](../../../../trillionnium/crates/trnm-pon-node/src/native_authenticated_tests.rs).
Its principal fixture is
`native_authenticated_signed_growth_branches_reopen_and_compact_queries`: it
actually admits 36 non-genesis blocks with 10 signed transfers across branches,
selects a reorganization, continues to height 34 through reward maturity and
cold reopens. Every retained state is compared with an ordinary native Node
given the same real packets. AAM1 membership, nonce and nonmembership queries
come from the integrated SQLite tree.

Only that fixture honors `TRNM_NATIVE_AUTHENTICATED_STATE_EXPORT_DIR`. It requires
a nonexistent destination and exports `native.json` plus a closed SQLite copy
created by `VACUUM INTO`. The manifest contains the actual complete retained
states, initial context, active selection and compact query. Independent readers
must use the database and reconstruct the claims; a manifest's presence is not
a pass.

Additional native tests cover old/new schema separation; missing persistent
nodes and corrupted commitments; block/delta/node/record write suppression;
late final-write corruption in fast and resumable selection; cancellation;
post-M06 signed qualified task output; and process exit with code 89 at the last
pre-commit fence. The process-exit parent test cold reopens and compares every
logical table to the pre-transaction state. This is an actual no-destructor
process exit, not a hardware power-loss experiment. The separately selected
child helper returns immediately outside that parent-controlled subprocess.

Migration tests separately cover checked signed branches, preservation of local
irreversible rows, pending reorganization phases, cancellation/publication
markers and corrupted source rejection. The complete fixture migrates six
non-genesis blocks with five signed transactions, including inactive branches,
completed and pending replay, a retained outbound wire, pool consumption/removal
and the exact AUTOINCREMENT frontier. It alone honors
`TRNM_AUTHENTICATED_MIGRATION_EXPORT`, creating a new directory containing
`native.json`, `source.sqlite` and `native.sqlite` before opening or recovering
the target. The independent storage reader compares every preserved SQLite cell
and reconstructs all retained states, native signatures and authenticated nodes.

The migration tests also exercise four pending-reorganization cursors, eleven
cooperative cancellation points, racing destination creation, canonical source
aliases, an actual local external-owner journal refusal, source SQL-writer
exclusion, post-commit changes and last-callback raw database/marker/receipt
changes. Five actual child-process exits with code 87 cover pre-visibility,
visible-but-fenced, pre-COMMIT, post-COMMIT and pre-publication states. Cold reopen
checks preserve the source, refuse pending copies and allow a fresh retry. These
are no-destructor process exits, not hardware power-loss qualification.

Source tests and this document do not
claim current hosted-head or prospective-merge success; those results must be
bound to the exact delivered commit.

## Batched paths and equivalent account-check primitives

The account delta adapter checks every changed leaf against the original parent,
then recursively merges sorted updates. It retains all old nodes and branch roots;
there is no garbage collector or history rewrite. Every node newly inserted by a
successful batch is reachable from its final account root. For `A > 0` final
accounts this limits new nodes to at most `2A-1` and their encoded payload to
`49A + 163(A-1)` bytes. At `A=65,536` that payload bound is13,893,469 bytes.
This excludes SQL keys, indexes, pages, WAL and all prior versions; it is neither
a total storage bound nor a measured allocation/latency result. Empty account
states insert no nodes. The test-only serial algorithm remains an independent
root, account and complete proof-byte reference for multiple retained branches.

The shared node primitives reuse prepared SELECT/INSERT statements while actually
executing every required row operation. A full account scan borrows each JSON
`Value` during deserialization, preserving accepted objects and exact two-element
arrays and the existing arbitrary-precision dispatch. Leaf decoding retains the
actual content hash, exact49-byte grammar and all field checks, then constructs
the same fields without allocating and hashing the identical encoding again.
Fork shape, child-path checks, cancellation and complete tree comparison remain.

`native_complete_account_verification_cost` is an explicit release-only ignored
observation which CI executes separately. It compares the original primitives
with the current complete account-tree check for actual retained states, in
alternating paired order, and retains every sample. A cached statement's SQLite
`Run` counter describes executions of that particular statement; it is not a
count of total statement preparations, physical reads or omitted work in the
reference arm. The clock excludes full State commitment, whole Node admission,
historical reconstruction and lock queueing. No speed threshold grants acceptance.

The separate release-only full-capacity native fixture uses65,515 preallocated
account/fixed keys, twenty reward reservations and a real signed quota. It must
reach the actual65,536-key limit through twenty real packets, reject premature
new-account entry, execute refund/maturity, admit cleanup-dependent entry and
recover a pending heavier-branch reorganization through two cold reopens. It
contains24 admitted packets and two signed transactions. No smaller limit,
artificial intermediate snapshot or fabricated height substitutes for this gate.
The ordinary debug ignore is explicit: both exact head and merge Rust lanes run
this test with `--release --exact --ignored`, retaining its actual result. The
small exported storage fixtures' independent reader does not independently
replay this larger capacity fixture.

The [monetary range relation](MONETARY_OBLIGATION_RANGES_V1.md) is an additional
explicit execution experiment over a checked full parent. It does not replace
this backend's native complete-State or non-account checks.

## Costs and remaining work

Incremental account persistence reduces which account nodes are newly written.
It does **not** remove full-state reads, full reference root construction,
non-account scans, per-state node availability checks or retained-history
validation. Those checks add real admission/recovery cost and must remain in
subsequent measurements. Persistent versions, all retained blocks, SQLite pages,
indexes and WAL have no newly established physical global bound here.

Further work must price and assign future state, obligation, storage and proof
service responsibility at admission, make complete obligation proofs continuously
available, measure growth and tail latency, and define physical retention/recovery.
Historical `state_at` can repeat the complete-state/account O(N) portions at each
of H replayed heights; retained snapshots do not establish a global recovery bound.
Partial-state execution or a changed consensus root requires its own explicit
version, migration and complete conformance evidence. This backend leaves those
requirements visible while making authenticated state part of the actual native
store lifecycle.
