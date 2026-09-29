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

The regression at height4101 is explicitly a storage fixture with assumed previously
verified history; it is NOT4101 generated PoN proofs. Native paged synchronization and
bounded-memory deep replay remain future work: this reference still materializes an
ancestry list, while full block/delta/event history is retained. Full-state root hashing
is not advertised as a scalable incremental-tree implementation.

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

Revision2 counts only live current-parent contributions. Zero-score evaluated and expired
records do not consume pending capacity. Same-parent artifact nullifiers are retained;
old-parent records can leave active state because submissions require the current parent.
Release proofs bind the payee directly, so retiring a candidate does not erase claim
ownership. Release claim windows reserve mandatory-expiry slots; remainder refunds at
the deadline. Noncurrent empty release objects then retire. This does NOT solve unlimited
same-parent tombstones, all account/task history or the global state-key ceiling.
