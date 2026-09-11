# M05 Transaction Admission / Mempool technical specification v1

Status: **implementation contract; candidate only**

## Authority

M05 owns canonical transaction preflight, authentication admission, nonce/replay
policy, fee and multidimensional resource reservation, mempool persistence,
replacement, proposal handoff, finality readback, expiry and tombstone garbage
collection. It never chooses canonical order and never mutates finalized
application state.

## Interfaces

- `SubmitTransactionV1(canonical_bytes, principal, lane, nonce, limits)`;
- `AdmissionViewV1(parent_root, height, epoch, parameter_hash)`;
- `AdmissionReceiptV1(tx_id, phase, reservation, durable_sequence)`;
- `ProposalHandoffV1(batch_id, ordered_tx_ids, parent_root, expiry)`;
- `FinalityReadbackV1(tx_id, finality_proof, receipt_root, state_root)`;
- `ReplacementV1(principal, lane, nonce, old_tx_id, new_tx_id, fee_delta)`;
- `GcPermitV1(finalized_height, replay_floor, proof_digest)`.

All IDs derive from exact canonical bytes and context. Callers cannot supply an
authoritative transaction ID, signer result, admission phase or finality fact.

## State machine

```text
Received -> Canonicalized -> Authenticated -> Admitted -> Reserved
 -> HandedOff -> Ordered -> Executed -> Finalized -> ReadBack -> Tombstoned
```

Terminal side paths are `Rejected`, `Expired` and `Replaced`. A transition
requires the exact predecessor, transaction identity and generation. Retry of an
identical request returns the original receipt. A different transaction at the
same nonce follows the versioned replacement rule or is rejected; it never
silently overwrites a durable record.

Admission is local and provisional. Proposal construction rechecks state,
nonce, balance, fees, access declaration and limits against the authoritative
parent root. M02 determines order; M06 determines execution; M08/M13 establish
finality and readback.

## Persistence and recovery

The WAL stores canonical bytes or their durable content-addressed location,
principal/lane/nonce, phase, reservation, handoff identity, acknowledgements and
a hash-chained sequence. `HandedOff` is not guessed after a crash. Recovery
queries the exact downstream durable receipt; ambiguity fails closed and keeps
the entry retained.

The `DurableTxJournalV0::compare_and_replace` port commits a replacement as one
compare-and-swap transaction: the exact old record becomes
`Tombstoned(Replaced { by: new_tx_id })` and the new record becomes `Admitted`.
The old-record digest must match and the new transaction must be absent. Both
records carry the same durable journal sequence. There is no implementation
that falls back to two independent appends. After a crash or lost response,
`load_latest` returns either the complete predecessor or the complete pair;
exposing just one member violates the journal contract and blocks adapter
acceptance. The coordinator retains no authority after an uncertain write or
a malformed durable receipt.

`Admitted` is a recoverable durable intermediate state, including after this
atomic replacement. Retry uses its existing receipt as the predecessor of the
`WalPersisted` append; it must not attempt to insert the transaction again.
The admission ACK is released only after that append, and exact admission
retry preserves the original WAL sequence. A recovered replacement tombstone
is already final for nonce ownership; a retry cannot resurrect the old intent.
These ports and crash-cut tests specify adapter obligations. They do not
provide a production storage adapter or physical power-loss qualification.

### Canonical durable record bytes v0

`TxRecordV0::encode_canonical_v0` and `decode_canonical_v0` define the closed,
IO-free record codec used by journal adapters. The prefix is the eight ASCII
bytes `TRNMTXR0`, followed by a big-endian `u16` version equal to zero. All
integers have their declared unsigned width and big-endian byte order; digests
are exactly 32 raw bytes. Variable byte strings have a big-endian `u32` length.
No padding, alternate integer encoding, implicit default or trailing byte is
accepted. A boolean is exactly `0` or `1`; each option is a one-byte `0` for
absent or `1` followed by its complete value.

| Record order | Encoding |
|---|---|
| Intent | chain ID, sender, nonce `u64`, fee bid `u128`, valid-until height `u64`, max compute `u64`, max state reads/writes/event bytes as three `u32`s, length-prefixed payload, length-prefixed authorization |
| Identity and phase | transaction ID, phase `u8`, lifecycle sequence `u64` |
| Optional values, in order | WAL sequence, proposal, ordered position, execution, finality, broadcast intent, broadcast receipt, tombstone |
| Proposal / ordered position | proposal ID + index `u32`; block ID + height `u64` + transaction index `u32` |
| Execution | transaction ID, complete ordered position, pre-state root, post-state root, receipt digest, event root, fee charged `u128`, success boolean |
| Finality | block ID, height `u64`, state root, finality proof digest |
| Broadcast intent / receipt | transaction ID, intent sequence `u64`, envelope digest; receipt additionally carries its transport receipt digest |
| Tombstone | reason `u8`: `0` replaced followed by replacement transaction ID; `1` finalized; `2` expired; `3` rejected |

Phase tags are `0` admitted, `1` WAL persisted, `2` proposed, `3` ordered,
`4` executed, `5` finalized and `6` tombstoned. Unknown phase, reason, option,
boolean or version tags fail closed. Payload and authorization retain their
respective 1 MiB and 16 KiB bounds. The maximum legal complete record is
`MAX_TX_RECORD_ENCODED_BYTES_V0 = 1,065,733` bytes, including 773 bytes of fixed
fields and tags. Total and declared byte-string bounds are checked before
allocation; reservation failure returns an error. Truncation is never repaired.

Both encoding and decoding validate the intent, recompute the transaction ID,
and enforce the same record invariants as coordinator recovery. Adapters also
call `validate_persisted_v0(expected_chain_id)` against their installed chain.
Ordinary phases require lifecycle sequence exactly `0..5`; early tombstones
require `1` or `2` according to whether WAL persistence occurred; a finalized
tombstone requires sequence `6` and all finality predecessors. Early tombstones
cannot retain proposal, ordered, execution or finality fields. Replacement IDs
are nonzero and different from the replaced transaction. Present WAL sequences
are nonzero. Proposal/ordered identities and indices, execution fee bounds,
and exact broadcast transaction/receipt bindings are rechecked. These local
checks do not authenticate signatures, finality proofs, or a journal's
predecessor history; those remain the existing typed authority and adapter
obligations. `canonical_record_digest_v0` remains unchanged: the storage codec
introduces no new transaction ID or receipt digest algorithm.

A tombstone can be removed only with a verified finality proof and a replay
floor that makes the nonce unspendable. Disk-full, fsync uncertainty, partial
WAL, database replacement and generation regression return unavailable or stop
the write path without losing a reservation.

### Candidate local file journal v0

The explicit `candidate-tx-journal` feature of
`trnm-durable-file-adapters-v0` provides `CandidateTxFileJournalV0`, a real
Linux file adapter for `DurableTxJournalV0`. The feature is off by default;
production activation and external rollback-protection constants remain false.
It uses the existing `fs2`, `rustix` and M05 core dependencies, without a second
transaction record schema or an in-memory journal substitute.

An existing canonical directory must be owned by the effective user and have
mode `0700`. The adapter retains its parent, directory and exclusive lock file
descriptors. Every file is opened relative to the directory with no-follow,
checked as a singly linked regular file owned by that user with mode `0600`.
The directory and lock inode bindings are rechecked during use. The retained
parent's ancestors remain a trusted deployment namespace: renaming/rebinding
those ancestors during an active owner is unsupported. Parent and child
directories are synced on initialization. These checks are not isolation from
a malicious process with the same OS identity or a hostile storage device.

`identity.v0` stores magic `TRNMTXJ0`, big-endian version `u16(0)`, chain ID,
journal ID, the three `u64` limits, and a domain-separated checksum (130 bytes).
Identity and limits must match exactly on reopen. Positive configured limits
may reduce, but never exceed, 100,000 committed frames, 1 GiB of committed frame
bytes, and 10,000 latest records. Collected history still counts toward frame
and byte limits. Replacement retains the old tombstone and adds one latest
record. Reaching any limit returns a capacity error without eviction, partial
admission, automatic compaction or a new receipt.

Committed frame names are zero-padded 20-digit positive sequences followed by
`.txf`. Each frame contains magic `TRNMTXF0`, version `u16(0)`, identity digest,
sequence `u64`, previous-frame digest, an operation `u8`, its payload, and a
32-byte domain-separated frame checksum. Operation `0` carries the expected
record digest and one `u32`-length-prefixed canonical record. Operation `1`
carries the replaced predecessor digest and two such records, old tombstone
first and new admitted record second. Operation `2` carries the transaction ID,
expected final-record digest and complete replay-floor witness. No unknown
operation, malformed name, sequence gap, checksum mismatch, record mutation,
unknown version, missing predecessor or trailing byte is repaired. Each frame
is bounded by `2 * MAX_TX_RECORD_ENCODED_BYTES_V0 + 256` bytes before read or
allocation. Recovery replays exact CAS and phase rules, reconstructs both
replacement receipts with one sequence, and rejects an independent append
that attempts to install a replacement tombstone or duplicate an active nonce.

The commit order is: exclusive create of `pending.frame`; write the complete
transaction frame; `File::sync_all`; `renameat2(NOREPLACE)` to its immutable
sequence name; directory `sync_all`; update the in-memory view; return the
receipt. Both replacement records share that one publication point and one
journal sequence. Every I/O error during publication poisons the owner,
including errors after rename or after the durable commit. Reopen accepts only
complete published frames. The two fixed unpublished staging names may be
removed under the lock; no committed frame is removed by recovery. After an
acknowledged commit, exact retry returns the original receipt. Before doing so,
the adapter rechecks identity, the current published head and the receipt's own
published frame. A live corruption/deletion fails and poisons the owner rather
than issuing a receipt from cached memory.

`delete_collected` compares the exact retained digest, requires a retained
Tombstoned record, matching sender, replay floor above that nonce, sufficient
finalized height and a nonzero authority reference. It appends a collection
frame, retains a replay fence and exact retry receipt, and removes only the
record from the latest view. It neither erases historical transaction bytes nor
verifies the public witness's cryptographic authority. The host must supply
that authenticated authority; this candidate storage adapter must not be used
as a proof that finality, replay-floor provenance or production GC is complete.

Repository tests exercise successful coordinator admission/replacement ACK
followed by restart and exact retry; returned failures and actual child-process
SIGKILL at seven cuts spanning partial write, file sync, publication, directory
sync and lost response; cross-process lock exclusion; malformed/tampered or
missing frames; identity and namespace substitution; hard capacity; and
collection/replay-fence recovery. Actual power-loss, filesystem/controller
flush guarantees and externally anchored coherent rollback detection remain
separate evidence requirements. A checksum chain detects interior corruption;
it cannot detect a complete older journal substituted before a new process
opens it. There is no unanchored compaction protocol in this version.

## Resource bounds

Limits cover transaction bytes, decoded nesting, signatures, state keys, read
and write declarations, proof work, gas dimensions, events, per-principal
entries, nonce gaps, replacements, global entries, retained bytes, WAL growth,
proposal bytes and readback work. Bounds are checked before allocation or
signature verification where possible. `u32::MAX` is not an operational count
limit.

## Security

The implementation rejects cross-chain replay, signer substitution, malformed
canonical bytes, nonce-lane confusion, fee overflow, replacement front-running,
reservation duplication, access-list underdeclaration and unauthenticated
broadcast. Rate limits are principal-aware and globally bounded. Admission
failure never leaks signer material or turns stale local state into a
deterministic block-validity claim.

## Observability and SLO

The `bounded-io-runtime-v1` profile reports admission p50/p95/p99, reason-coded
rejections, WAL/fsync latency, entries and bytes by phase, replacement rate,
handoff age, finality/readback latency, tombstone age, replay rejection and
resource saturation. Submitted TPS is not committed goodput.

## Verification and evidence

Required tests cover malformed encodings, duplicate and gap nonces, cross-lane
replay, concurrent replacement, arithmetic overflow, disk-full and every WAL
crash cut. End-to-end evidence follows one exact transaction through signature,
admission, broadcast, ordering, execution, finality, proof readback, restart,
duplicate retry and bounded GC. Mutants must demonstrate that removing
predecessor, generation, proof or replay-floor checks is detected.

## Activation boundary

Production reachability requires real CheckTx/RPC ingress, production signer and
context resolvers, durable network broadcast, exact handoff/readback recovery,
tombstone GC and unchanged-head crash evidence. Candidate WALs and fixtures do
not activate this boundary.
