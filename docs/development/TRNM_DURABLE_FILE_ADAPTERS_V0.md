# TRNM Durable File Adapters v0

Status: repository-owned production-shaped adapters; **not activation evidence**.

Package: `trnm-durable-file-adapters-v0`  
Primary module: M15  
Secondary module: M13  
Protocol: `poco-bft-v0`

## 1. Authority journal

`FileAuthorityCoordinatorV0` implements `AuthorityCoordinatorV0` with a
process-exclusive file lock and a fixed-size append-only record format. Every
record binds:

- node identity digest;
- operation id, height, view, block, parent, and proposal digest;
- exact authority stage and global durable sequence;
- retained facts digest;
- previous record digest; and
- current record digest.

Opening a journal scans the complete file. A partial tail, bad magic, changed
identity, invalid operation binding, non-monotonic sequence, broken hash chain,
stage skip, invalid next-height transition, or digest mismatch fails closed.
No invalid tail is truncated or silently repaired.

An operation can start only at an empty journal or after the previous operation
reaches `OutboundPublished`. The next operation must be at the exact next
height, use a new operation id, and name the previous block as parent. Exact
command replay returns the retained receipt; a replay with changed facts is a
receipt-substitution error.

A new record is returned only after `write_all` and `sync_data`. Any write or
sync error poisons the live adapter. Recovery then requires closing and
reopening the journal so the complete on-disk chain is revalidated.

## 2. Snapshot generation target

`AtomicSnapshotFileTargetV0` implements `NonDestructiveInstallTargetV0` with:

```text
root/
  snapshot.lock.v0
  CURRENT.v0
  staging/generation-N/
  generations/generation-N/
```

The current pointer is checksummed and binds generation, height, state root,
and manifest digest. Staging is single-writer under the same exclusive lock.
Each chunk is written through a unique temporary file, synchronized, renamed,
and directory-synchronized. Same-index exact replay is idempotent; changed
bytes fail as substitution.

Commit verifies the expected current root, exact manifest, closed count/byte
bounds, presence of every expected chunk, and absence of unexpected staging
files. The staging directory is synchronized, renamed to an immutable
generation, and a synchronized temporary current pointer is atomically renamed
over `CURRENT.v0`.

The pointer rename is the linearization point. The method never returns an
error after that point, because a caller must not abort a generation that may
already be serving. A post-rename directory-sync failure is retained through
`post_commit_directory_sync_degraded()` and requires operator quarantine plus
external physical-power-loss qualification.

An explicit recovery method removes only unreferenced staging and generations
newer than the current pointer while holding the exclusive lock. It never
rewrites or deletes the referenced generation.

## 3. Required adapter wiring

The authority adapter is suitable only for the Node Commit Ledger boundary. It
does not implement the network, application seal, SafetyRules, signer, finality,
checkpoint, or outbound transport; their facts must be supplied by the
canonical coordinator in the mandated stage order.

The snapshot target stores already verified chunks. It does not choose a trust
anchor, verify checkpoint proofs, compute the chunk root, or recompute the
application state root. Those remain mandatory in `trnm-state-sync-v0` before
installation.

## 4. Qualification matrix

Repository qualification must include:

- clean open and exclusive-lock conflict;
- complete multi-stage write, close, reopen, and recovery;
- exact replay and changed-facts rejection;
- complete first operation followed by exact next-height begin;
- partial-tail, hash-chain, identity, stage, and parent mutation rejection;
- snapshot chunk idempotence and substitution rejection;
- missing, extra, and oversized chunk rejection;
- current-root CAS conflict preserving the old pointer;
- abort before pointer swap removing only unreferenced state;
- successful install followed by close/reopen current-pointer recovery; and
- production dependency closure excluding every lab/candidate crate.

## 5. Non-claims

Repository tests and `sync_data`/directory synchronization calls do not prove
specific storage hardware, kernel, mount, controller-cache, virtualized disk,
or abrupt power-loss behavior. This package does not close real HSM/device
signing, physical power-loss, independent multi-host, audit, soak, governance,
release, public-testnet, activation, or G5 gates.
