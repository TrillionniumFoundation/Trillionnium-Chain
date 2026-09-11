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

A tombstone can be removed only with a verified finality proof and a replay
floor that makes the nonce unspendable. Disk-full, fsync uncertainty, partial
WAL, database replacement and generation regression return unavailable or stop
the write path without losing a reservation.

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
