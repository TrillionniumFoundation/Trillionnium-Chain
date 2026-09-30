# S2 — initialization, branch state and independent effects

This revision replaces the S1 storage layout; it is not an in-place database migration.
Exact code: `formal/pon-nakamoto-v1/ledger.py`; regression: `test_invariants.py` plus
all existing `DiskReorgTests` in `test_contracts.py`. The Python owner remains the
reference persistent owner; selecting native application execution does not make this
SQLite owner a completed native node.

## Owned initialization and schema identity

Before opening a new database, acquire the nonblocking exclusive owner lock. Reject
symlink leaf paths and nonempty unknown namespaces. Persist `initializing.json` containing
exact schema digest, parameter commitment and genesis. Use create-exclusive/no-follow,
fsync the intent and directory. Create all tables, indexes, metadata, genesis block,
initial KV and genesis snapshot in ONE IMMEDIATE transaction. Remove the intent and
sync the directory only after successful commit.

Four actual child-process cuts are `init-intent`, `init-schema`, `init-before-commit`
and `init-committed`. Reopening an exact owned intent recovers; an empty database without
that intent refuses `INITIALIZATION_INTENT_REQUIRED`. Wrong context refuses. Foreign
schema, extra triggers/views/indexes or different SQL projection refuse before writable
PRAGMAs. This is not protection against every hostile ancestor/sidecar replacement.

## Tables and authoritative writers

| Table | Identity | Responsibility |
|---|---|---|
| metadata | key | exact parameters and schema digest |
| blocks | block id | verified parent,height,512-bit work,header,body,proof,root |
| deltas | block,key | nullable before/after; absence differs from empty bytes |
| active | singleton | tip, logical generation, physical state_slot |
| kv | physical slot,key | canonical values for one published or staged view |
| reorg | singleton | old/new tips,logical generation,steps,cursor,status |
| events | generation,ordinal | ordered remove/add notifications |
| snapshots | block id | local root-verified checkpoint state |

`state_slot` is not a consensus field. Ordinary append applies only changed keys and
publishes head/generation/event inside one transaction. SQLite read transactions see
the complete prior or next state; logical generation increments without a full KV copy.

## Fork recovery

A real fork records exact ordered detach and attach steps and copies to one staging
slot. Each delta and cursor advancement commits together. Check expected old values,
recompute target root, then atomically publish tip/generation/slot/events and retire old
physical slots. Existing readers retain their SQLite snapshots. The eight original
cuts remain: intent; two detach cuts; three attach cuts; before-publish; published.
No partially changed state is published as a coherent root.

`recover` first completes the exact existing intent, then inspects the indexed set of
fully verified stored tips. A strictly heavier tip is activated even if a process died
between `admit` and `activate`. Equal work leaves the current tip unchanged. A peer's
claimed work total never becomes an indexed authoritative block record.

## Beyond4096 and bounded cache retention

Every128 admitted heights can retain a local checkpoint. Verify its state against the
immutable stored block root before using it. Keep at most64 non-genesis snapshots plus
genesis; missing cache falls back to original deltas, not an invented finality cutoff.
Parent heights decrease exactly and cycles reject. Progress callbacks occur every256
ancestry/replay records. All replayed delta preconditions and block roots are checked.

The storage regression above4100 includes an explicit previously-verified-history
premise; it is not generated work. The separate long_history campaign mines/verifies
actual proofs, includes signed transfers and executes a shallow fork beyond4096.
Its runtime/source/filesystem receipts are recorded separately. Replay spools the
ancestry index to an8KiB bounded buffer; state maps and root hashing remain full
reference values, not a complete incremental native authenticated tree.

## Effects and revoke linearization

Independent `EffectJournal` uses its own WAL/FULL database. `enter` validates exact
operation/payload/generation, then holds BEGIN IMMEDIATE across revocation lookup,
duplicate lookup and insert. `revoke` uses the same serialized write boundary. When
revoke commits first, entry leaves no row. When entry acquired the write boundary first,
a concurrent revoke waits; the existing entry is an observed fact, not proof the remote
effect has or has not occurred. Crash after commit cannot authorize a second dispatch.

A real Hepta final-use permit and current owner/generation must still be checked before
the physical call. This module does not issue that permit, undo an already performed
operation, or resist simultaneous rollback of every independent record. Local revocations
and effect history never follow chain undo. Compensation is a newly authorized action.

## Long-lived application records

Revision3 counts only live current-parent/current-round candidates against pending
capacity. Zero-score evaluated and expired candidates no longer consume that capacity.
Each signed contribution additionally binds its128-block intake round; a round admits
at most512 historical candidates. On a new round, old candidates and their same-round
artifact nullifiers retire, while the old signed payload is rejected by its round.
A new parent similarly invalidates old-parent admission. The new round is not evidence
of a new useful contribution: utility still requires current-parent evaluation.

Release claims verify the payee against the retained allocation root without requiring
a retired candidate row. Claim windows reserve mandatory-expiry capacity and refund
remaining escrow at the deadline. Expired task/quota objects have nonce/context-derived
identities; their deletion cannot reopen the same signed creation. Accounts, registered
work and full block/delta/event history still need a future bounded retention policy.

## Revision3: bounded-memory ancestry index

`state_at` stores ancestry IDs in an8KiB spooled file and seeks it backwards for replay.
Missing checkpoints no longer create an unbounded in-memory ID list. Strictly decreasing
validated heights rule out cycles; every recovered snapshot/delta is still root checked.
A progress callback every256 records can abort, closing the spool; a later call resumes
by verified replay rather than trusting a partial root. State maps and root recomputation
remain full reference values, and this is not a persistent resumable native WAN sync.

The storage-only4102-record regression labels its premise explicitly. The separate
`long_history.py` campaign creates actual proofs and signed transactions above4096 and
performs a shallow competing fork; its logical clock and real SQLite evidence are reported
separately from the physical-host UTC campaign. Neither establishes physical power loss.

## M08 procedure boundary and retry contract

`M08.PlanReorg` is the planning phase of `Ledger.activate(target, cut=None)`, not a
separate exported plan constructor. The target is an already admitted block identifier;
callers cannot supply its work or replacement undo steps. Existing pending intent is
completed first. Equal/lower work returns the active tip without new events. Ordinary
extension without a fault callback updates deltas/head/generation/event in one transaction
on the existing slot. An actual fork finds the common ancestor and persists the staging
copy plus exact detach/attach intent before any fork step. The current ancestry lists
are in memory and staging is a full copy: native bounded planning is still work to do.

`M08.RecoverAndPublish` is `Ledger._recover_intent(cut=None)`. It requires
`active == (old_tip, next_generation - 1)`, applies each step with its cursor transaction,
checks the final root, and publishes the active tuple/events/done/slot retirement together.
`Ledger.recover` then separately selects the best verified stored work. Do not conflate
completion of an existing intent with discovery and activation of a later heavier tip.

| Interruption or rejection | Durable state and required next action |
|---|---|
| Before staging commit | Old published state remains; caller may recompute the same target plan. |
| After intent commit | Old published state remains; resume this exact persisted intent before new admission. |
| During a delta transaction | Either prior cursor/state or next cursor/state survives; never advance one without the other. |
| Wrong before-image / generation / target root | Retain committed evidence and fence admission; diagnose corruption instead of deleting intent or manufacturing a new root. |
| Before final publication commit | Old active view remains; replay cursor/root check and retry publication. |
| After publication, before return/ACK | Done marker and events already exist; repeat recovery returns current tip, without duplicate events or effects. |
| After admission, before activation intent | Startup recovery inspects stored fully verified tips and activates strictly heavier work. |

`UNKNOWN_PARENT`, `GENERATION`, `SCHEMA`, `UNDO_ROOT`, `ROOT` and underlying SQLite/I/O
errors are not interchangeable. SQLite error or local capacity exhaustion is not proof
that the remote block is invalid. A process exception is not proof of a remote API effect.
No recovery operation clears `EffectJournal` or creates a local Hepta final-use token.
The concrete module contract and retained crash tests are linked from
[M08](../../../modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md).

## Incoming history consumer at the existing owner

N2 in NETWORK_CLIENT defines the bounded page producer/receiver. It imports actual
header/body/proof records through Ledger.admit, never through the local checkpoint
trust premise. A per-page failure can retain a fully verified prefix; retry or reopen
uses those immutable records. Transport completion, local active-tip selection and
current transaction confirmation are separate observations. No new tables, authority
owner, genesis parameters or schema migration are introduced by this client continuation.

## Native compute caches do not replace this durable owner

The optional M06 native session and M00 compressed commitment tree are disposable
in-memory caches. `Ledger` remains the only block/delta/reorg/active-pointer SQLite owner.
A crash or ambiguous compute reply closes the cache. Restart recovers this same durable
namespace, selects the verified branch, and opens a new root-bound compute session.
Different parent state resets the session; no session sequence is a commit receipt,
undo checkpoint, authorization or evidence that a physical effect happened.

The native commitment updates changed paths, but durable maps, ancestry, application
scans and Python verification still have complete-state costs. Native paged storage,
state lifetime economics, the 16 MiB bridge capacity gap and physical power-loss testing
remain open. Existing M08 crash/reorg tests run with the explicit session backend too;
this tests composition with the reference persistent owner, not a complete native node.

## Native branch owner continuation

The M15 `trnm-pon-node` composition implements M07/M08 in `src/store.rs` without
opening the reference Ledger's database. Its fresh `native.sqlite` owns metadata,
blocks, before/after deltas, active generation/slot, KV, reorg intent/cursor, ordered
steps/events and root-checked local snapshots. A 512-bit big-endian indexed work value
is derived at native admission; no peer-supplied work total enters this table.

Initialization writes and syncs an exact context/schema intent before creating schema
and genesis in one SQLite transaction. Reopen checks the schema and context read-only
before a writable connection. Unknown empty stores, extra triggers, mismatched genesis
and duplicate native writers reject. WAL/FULL, owner file locks and inode/symlink checks
are implemented; full descriptor/sidecar race protection and coherent disk rollback
anchors remain unqualified. No process-exit test is called a physical power-cut test.

Block plus deltas commit together. A direct extension applies its deltas, checks its
root and publishes tip/generation/event atomically without copying all persistent KV.
A real fork prepares a separate slot and disk-backed ordered detach/attach steps in one
transaction. Each step validates before-images and advances its cursor atomically.
Only a matching final root permits one atomic active/events/done/old-slot publication.
Recovery completes the intent, then selects any strictly heavier verified stored block;
this includes an admission committed before its activation intent. Equal work retains
the current chain. Corrupt generation, steps, root or delta preconditions remain fenced.

Reconstruction spools ancestor identities on disk and checks snapshots/deltas/roots;
retention is not a finality threshold. Full maps/root computations and long history
remain resource costs. No Hepta operation journal, provider effect or user database is
inside this chain namespace or its undo transaction.
