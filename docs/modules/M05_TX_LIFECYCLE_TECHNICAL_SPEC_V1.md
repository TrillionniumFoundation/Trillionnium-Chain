# M05 Transaction Admission / Mempool technical specification v1

Status: **implementation contract; candidate only**

## Authority

M05 owns canonical transaction preflight, authentication admission, nonce/replay
policy, fee and multidimensional resource reservation, mempool persistence,
replacement, proposal handoff, finality readback, expiry and tombstone garbage
collection. It never chooses canonical order and never mutates finalized
application state.

### Source map and implementation status

| Source | Present behavior | Planned host responsibility |
|---|---|---|
| `trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs` | Pure intent/phase/receipt rules and signing/ID digests | Resolve authenticated nonce/balance/height context |
| `trillionnium/crates/trnm-tx-lifecycle-v0/src/production.rs` | `ProductionTxCoordinatorV0`, durable journal/sign/broadcast/readback ports | Real services, proof verification and restart orchestration |
| `trillionnium/crates/trnm-tx-lifecycle-v0/src/codec.rs` | Closed durable record bytes v0 | Adapter interoperability, not a new transaction signing format |
| `trillionnium/crates/trnm-mempool/src/lib.rs` | Bounded/lane admission queues | Bind queued work to exact durable M05 IDs |
| `trillionnium/crates/trnm-application-tx-builder-v0/src/lib.rs` | Strict JSON/canonical application building | Explicit adapter; its object schema is not implicitly `TxIntentV0` |
| `trillionnium/crates/trnm-durable-file-adapters-v0` | Candidate file journal behind explicit feature | No production rollback anchor or authenticated GC source |

## Interfaces

### Submitted intent and identity

The proposed private-devnet HTTP interface is defined in M14 at
`POST /dev/v1/transactions`; M05 receives an exact typed `TxIntentV0`.
Fields are chain ID/sender (32 bytes each), nonce `u64`, fee bid `u128`,
valid-until height `u64`, compute `u64`, reads/writes/events `u32`, nonempty
payload (<=1 MiB) and nonempty authorization (<=16 KiB). Integers and byte
encodings follow the M14 request contract before constructing this value.
Unknown fields and independent nonce lanes are rejected: v0 has only the
`(sender,nonce)` domain. Future AI-v1 lanes require a different signed profile.

Use existing `TxIntentV0::signing_digest` domain `trnm.tx.signing.v0` and
`tx_id` domain `trnm.tx.id.v0`; the latter binds signing digest and authorization.
`Digest32V0::hash` length-prefixes domain and every part with big-endian `u64`.
Never hash JSON text, a displayed tx ID or a transport frame as a replacement.
`AuthorizationVerifierV0` must authenticate sender against that exact signing
digest; an API principal/rate-limit token does not replace sender authorization.

### Operation ports and receipts

| Operation | Input and predecessor | Output / required producer |
|---|---|---|
| `admit_and_persist` | Signed intent, trusted current height and recovered journal | `TxAdmissionReceiptV0 {tx_id,wal_sequence,record_digest,durable_receipt_digest}` |
| `persist_proposal` | WAL-persisted tx and exact proposal/index | Durable Proposed record; M02 proposal construction |
| `persist_ordered` | Proposed record and verified block/height/index | Durable Ordered record; M02/M08 canonical ordering |
| `persist_execution` | Ordered record and matching execution receipt | Durable Executed record; M06 execution |
| `sign_and_broadcast` | Durable record plus verified Core/Safety permit | Persisted broadcast intent/receipt; M03 signer and M04 broadcaster |
| `apply_finalized_readback` | Exact tx ID, authenticated finalized source | `FinalizedReadbackV0`; M08 commit and M13 proof checks |
| `tombstone_and_collect` | Finalized tx and authenticated replay-floor witness | Durable tombstone/collection receipt; M07/M08/M13 source |

Initial admission returns phase `WalPersisted`; `wal_sequence` identifies the
first durable admission, not necessarily the latest journal frame. Exact retry
preserves tx ID and original WAL sequence; after phase advancement the returned
record/receipt digest can identify the newer durable record. The planned API
exposes that current phase explicitly instead of claiming all receipt bytes are
unchanged forever. Receipt digests are local persistence facts, not finality proofs.

## State machine

```text
Admitted(0) -> WalPersisted(1) -> Proposed(2) -> Ordered(3)
 -> Executed(4) -> Finalized(5) -> Tombstoned(6)
```

These are actual `TxPhaseV0` tags. Parsing/authentication/reservation happen
before durable admission; ReadBack is a query, not another stored phase.
Rejected input has no accepted record. Early replacement/expiry/rejection
uses a typed tombstone only where the v0 phase rules permit it.

### Admission and replacement algorithm

1. Enforce transport/decoded resource limits and checked arithmetic. Validate
   chain, nonzero fee/expiry, resource limits and authorization shape.
2. Resolve current height, account nonce and spendable balance from one immutable
   authenticated parent view. The planned dev host permits one active next nonce
   per sender (or its exact replacement), avoiding an unimplemented nonce-gap
   pipeline. This is local admission policy, not a new block-validity rule.
3. Verify authorization; an exact already-recorded intent returns its durable
   identity even if the present admission view has advanced. Never reinsert it.
4. Reserve finite queue/byte capacity and local fee/resource budget keyed by
   sender/nonce; do not debit canonical state. Proposal construction revalidates
   nonce/balance/expiry against its actual parent root.
5. Call `admit_and_persist`; fresh intent commits Admitted then WalPersisted
   using compare-and-append. Only acknowledge after the second durable receipt.
6. A different same-nonce intent may replace only Admitted/WalPersisted state,
   and fee must be strictly greater. v0 does not implement a 10% fee-bump rule.
   Atomic compare-and-replace commits old tombstone plus new Admitted record;
   then persist the new WalPersisted transition before ACK.
7. On any uncertain write or malformed receipt, poison the coordinator, stop
   writes and recover from the journal. Do not release the reservation until
   exact old/new durable state is resolved. A proposal race returns conflict.

### Proposal, broadcast and result algorithm

Proposal selection consumes eligible WAL-persisted records under byte/work
limits, rechecks the parent view, and persists the exact proposal/index before
handoff. M02 selects canonical order; a local FIFO is not consensus order.
Verified ordering and execution produce separate durable transitions. Expiry
cannot erase an already ordered transaction; readback resolves its final outcome.

`sign_and_broadcast` verifies `CoreSafetyPermitClaimV0` against the current durable
record, obtains a signature from `NonExportableTxSignerV0`, persists its broadcast
intent, calls `AuthenticatedTxBroadcasterV0`, checks the exact returned envelope
binding, then persists the broadcast receipt. This node-side envelope signature
is separate from the user's existing transaction authorization. A caller cannot
supply a fabricated permit or private signing key through RPC.

Lost broadcast response leaves an uncertain effect. Retry/readback uses the same
intent sequence/envelope identity; it cannot invent a new signed effect merely
to clear a timeout. Signer idempotence and durable peer receipt are M03/M04 duties.
`FinalizedTxReadbackSourceV0` must verify the chain/epoch/validator trust path,
finality certificate and transaction execution binding before returning a claim.
The coordinator's digest/field checks do not implement that cryptographic verifier.

### Finalized receipt and garbage-collection authority

The current local lifecycle record carries tx ID/sender/nonce, block/height/index,
execution pre/post roots, receipt/event roots, fee, execution status, finality
proof digest and optional broadcast receipt. Recording these fields does not
cryptographically prove each one. Remote V1 responses expose only the verified
fields defined below; other execution fields remain explicitly local observations
unless independently replay-proved. An included failed execution must not be
reported as an unsubmitted transaction.

Current v0 requires `finality.state_root == execution.post_state_root`. Preserve
that check. If execution's post-root is an intermediate transaction root in a
multi-transaction block, the general receipt cannot be represented by v0 merely
by copying the block root over it. Planned `FinalizedTxClaimV1` must separately
bind the exact committed transaction/receipt and final block root under M13,
without treating an intermediate transaction root as a header commitment. Until that version is implemented and reviewed, return `PROOF_UNAVAILABLE`
for unsupported multi-transaction proof mapping; do not manufacture finality.

### Planned public native candidate admission profile

`native-public-candidate-v1` is the selected first live-client profile. It accepts
exact `BuiltCanonicalTxV0::from_exact_outer_bytes_v0` bytes: canonical outer
`SignedCommandEnvelopeV1` JSON containing canonical `CanonicalTxV1` JSON. Reject
duplicate/unknown fields, noncanonical bytes, invalid Ed25519 signatures, wrong
chain, unknown application signer/role/key and outer/inner sender or nonce
mismatch. Use existing `SignedCommandEnvelopeV1::tx_hash()` as
`native_tx_hash`: its domain binds signing bytes and the signature. Preserve the
outer bytes without normalization. This hash is distinct from M05 `TxIdV0`;
fee_limit/max_gas and wall-clock expiry must not be translated into invented
fee_bid, multidimensional limits or valid_until_height. The native proof result
may derive this native hash from its authenticated exact bytes after strict
canonical decoding; it may not advertise an M05 intent ID.

The implementation must extend `trnm-poco-node/src/tx_admission_wal.rs` and its
`NodeOwnedTxAdmissionBoundaryV0`, then connect it to the running consensus owner.
The existing strict CheckTx, signer/context resolvers, WAL/FULL mode, exclusive
lock, reservation conflict and sealed native readback remain the authority.
Neither the disconnected legacy RPC map nor the G1 process fixture is the live
submission route. Namespace is a domain-separated commitment to genesis,
chain ID and admission profile. Canonical signer identity comes from the pinned
application policy, stays stable for that logical signer across key rotation,
and is never supplied by the request.

#### Canonical body durability and explicit WAL migration

A new, versioned native-body record must atomically bind namespace, native hash,
exact outer bytes, outer-byte SHA-256, existing admission metadata, receive
sequence and profile digest to its nonce reservation before ACK. Sequence is a
checked monotonically increasing u64 assigned in that SQLite transaction.
Uniqueness is enforced for native hash and for canonical signer/nonce. Exact
retry returns the original sequence/status; another envelope using the reserved
nonce is `NONCE_CONFLICT`. Recompute native hash and metadata from retained bytes
when opening the store, never trust the stored hash alone. No private key is stored.

Schema v2 contains metadata/digests but no recoverable outer body. Opening it
under the new profile must return `ADMISSION_MIGRATION_REQUIRED`, not create an
empty replacement. An explicit exclusive migration to the next schema validates
old schema/identity/receipts/tombstones first. Every nonterminal Reserved row must
have a caller-supplied exact outer preimage that reproduces its complete stored
metadata and signature; missing or conflicting preimages abort before mutation.
Every HandedOff row must first be resolved by authentic application/finality
readback under the existing recovery owner, or migration remains unavailable.
Expired Reserved preimages may be retained for audit but cannot reenter the
ready queue. Preserve all terminal receipts/replay tombstones. Allocate migrated
receive sequences in deterministic signer/nonce/native-hash order (historical
arrival order is unavailable); label this ordering in the migration record.
Write the new body rows, schema and migration commitment in one transaction;
crash before commit leaves v2, after commit leaves a fully validated new schema.
Fresh isolated campaign namespaces use the new schema directly.

#### Live queue, batching and finalization

Candidate defaults, bounded further by authenticated parameters: at most 256
pending transactions, 16 MiB retained pending outer bytes, 256 KiB per outer
envelope; a proposal takes at most 64 transactions and 1 MiB total canonical
payload bytes including CEV0 framing. Reject saturation before allocating a new
reservation. Select by receive sequence; nonce/balance and expiry are rechecked
against the exact speculative parent selected by Core. A deterministic invalid
transaction receives a durable local rejection; unavailable/corrupt state pauses
proposal work and is not mislabeled transaction invalidity. Do not silently
change signed fees, contents or the order of an already reserved proposal batch.

Before exposing a proposal, persist its selected native IDs and exact
parent/block/view binding. Live in-flight leases owned by this process do not
block unrelated admission; an unresolved lease recovered from a previous process
continues to block serving until authenticated reconciliation. Competing branch,
timeout and restart never authorize `HandedOff -> Released` from local absence
alone. Reproposal of identical bytes requires an owner-verified current branch
and nonce check; committed/expired/conflicting identities remain fenced. Shutdown
retains accepted bodies and reservations rather than dropping a lease into an
unrecorded cancellation. If effect certainty is lost, stop that owner and recover.

Upon each actual finalized application commit, join exact native bytes/position,
receipt commitment and Core finality; persist the inclusion proof and commit
receipt before publishing `included-finalized` or collecting queue bodies.
Recovery handles the application-committed/queue-unacknowledged cut idempotently.
Persist historical proof/evidence bytes so a later finalized tip does not erase
queryability. The local pending/proposed/rejected status is not a cryptographic
execution-result field. Empty Regular successors must keep consensus advancing
when the queue drains: a lone user transaction needs two certified descendants.
Empty blocks have frozen empty payload/receipt roots and no user receipts or
business-goodput credit; generated workload transactions are not a substitute.

Acceptance covers exact retry after lost ACK/restart, body/hash/nonce corruption,
v2 migration cut points, unrelated admission while a proposal is in flight,
leader change/reproposal, deterministic rejection versus local storage failure,
one submitted transaction plus empty successors, and durable historical proof
query after a later commit. These are implementation obligations, not claims that
the current native proof verifier already provides a networked lifecycle.

### Implemented native inclusion boundary

`trillionnium/crates/trnm-tx-lifecycle-v0/src/finalized_proof_v1.rs`
implements the native-byte subset of the following contract.
`NativeTxProofPackageV1::{encode,decode_exact}` enforces the exact schema/framing,
nonempty required fields, no suffix and at most 32 siblings per branch.
`verify_native_tx_inclusion_v1` combines strict Ed25519 three-chain finality
with both ordered memberships. The target must equal the oldest finalized
header; a valid later QC does not retarget the claim. `OrderedInclusionProofV0`
in consensus-types shares the frozen kind/index/count/level hashes and requires
an odd tail's duplicate sibling to equal the current digest.

The separate `verify_native_tx_epoch_inclusion_v1` takes
`NativeTxEpochProofContextV1`: independently trusted old set/parameters, complete
eight-root epoch evidence, expected target and local limits. It calls the
strict epoch-transition boundary, including signed timeout certificates when
views skip. Receipt parsing and transaction-count caps use the authenticated
new parameters returned by that boundary. Combined evidence plus package must
fit the smaller caller budget and 4 MiB; one caller-supplied CEV0 work budget
remains charged after rejection. The epoch proof digest binds every evidence
preimage plus the exact package. Ordinary admission never retries a failed
proof using the epoch route.

Only these functions issue `VerifiedNativeTxInclusionV1`. Its read-only facts
are native bytes, position/count, exact finalized header and receipt-bound
gas/fee/events. It authenticates neither the complete M05 admission `tx_id`
nor execution status or intermediate state roots. `SignedCommandEnvelopeV1`
and its inner `CanonicalTxV1` still lack some canonical M05 intent fields;
therefore `FinalizedTxClaimV1`, lifecycle promotion and public RPC publication
remain integration work. Existing v0 finalization semantics are unchanged.

`finalized_proof_v1_tests.rs` and `finalized_proof_v1_epoch_tests.rs` use real
Ed25519 signatures and cover odd counts/positions, kind/count/index/receipt
substitution, wrong target/trust set, exact package truncation/overflow/suffix,
signature corruption, byte/count/work caps, complete epoch evidence and skipped
views. The verified result cannot be constructed externally (compile-fail test).

### Planned V1 multi-transaction proof contract

`FinalizedTxClaimV1` is a new candidate readback variant, not a relaxation of v0.
Its proof package has this exact local layout: u16-be schema=1; Bytes canonical
v0 target header; Bytes canonical v0 finality proof; Bytes exact canonical
application transaction at that block position; Bytes canonical
`ExecutionReceiptCommitmentV0`; u32-be index; u32-be item_count; List<Hash32>
payload siblings; List<Hash32> receipt siblings. Bytes/List use u32-be lengths;
unknown schema, trailing bytes and integer overflow reject. This is a local RPC
proof envelope, never a new consensus signing preimage. Total package is bounded
by the smaller authenticated proof budget and 4 MiB; the count is bounded by the
selected native block transaction limit, and each branch has at most 32 hashes.

M13 verifies the package as follows:

1. Strictly verify finality under the independently installed trust context,
   expecting the exact target header/block/epoch/height. Merely carrying that
   header inside a valid proof for a different target is insufficient.
2. Require 1 <= item_count and index < item_count. Decode the receipt exactly;
   require its transaction_index equals index and payload_leaf_hash equals
   `ordered_leaf_digest_v0(RootKind::Payload, index, transaction_bytes)`.
3. Verify both ordered branches against the target header's payload_root and
   receipts_root using frozen `ordered_root.rs`: kind Payload=0/Receipts=1,
   index-bound leaves, level-bound nodes and count-bound outer root. Starting at
   level 0, orient siblings by index parity, then halve the index and replace
   width by ceil(width/2). An unpaired right child duplicates the current digest;
   its supplied sibling must equal it. Require exactly ceil(log2(item_count))
   siblings (zero when count=1) and reject extra or missing levels.
4. Recompute the M05 signing digest and tx_id from the entire admitted intent,
   including chain/sender/nonce/fee/expiry/resource limits/payload/authorization.
   Require the selected M06 native adapter to prove one of exactly two bindings:
   `ExactIntent` (the native transaction commits the complete canonical signed
   intent byte-for-byte), or `IdCommitment` (strict native decoding yields a
   consensus-validated full tx_id field equal to that recomputation). Its profile
   hash fixes the codec and execution checks; neither a caller flag nor an
   arbitrary byte-substring search is a decoder. The adapter must authenticate
   the complete commitment during execution as well as readback. An extraction
   that drops fields and maps different intents to the same proved payload
   cannot supply either binding. Unsupported profiles return `PROOF_UNAVAILABLE`;
   native payload inclusion alone can be returned with the M05 tx_id labelled
   local correlation, but cannot advance a remotely verified M05 claim.
5. Issue a private verified readback containing tx_id, target block/epoch/height,
   transaction index, the target block state_root, and proved gas_used,
   fee_charged and events. Persist its proof digest plus exact target/receipt
   identity before publishing the finalized lifecycle result.

The frozen receipt commits index, payload leaf, gas, fee and events; it does
**not** commit an intermediate transaction post_state_root or an arbitrary
success-status string. Such fields stay local execution observations unless
independent deterministic replay or a separately versioned commitment proves
them. The API must distinguish `included-finalized` from any application-specific
outcome inferred from proved events. A proof must not authenticate extra fields
merely because they accompany a valid branch.

Exact proof retry is idempotent. Wrong target, kind, count, index, sibling,
receipt bytes, full-intent commitment or trust context rejects without phase
advance. Missing archived receipt/body is unavailable; it is not license to
synthesize a leaf. Required vectors cover a three-transaction block at indices
0/1/2, odd-tail duplication, one-item tree, count substitution, extra branch
hash, target-header substitution and unproved intermediate-root/status claims.
Also prove rejection when two intents differ only in fee, expiry, resource limit
or authorization yet an adapter emits the same native transaction bytes.
M06 retains the canonical receipt bytes; M08 supplies finality; M13 owns proof
verification; M14 exposes only the verified result. V0 callers retain their old
strict contract until this separate path is implemented and qualified.

GC obtains `ReplayFloorWitnessV0` from authenticated finalized account state:
account matches sender; `minimum_replayable_nonce > tx.nonce`; finalized height
covers the tx; authority digest binds the verified state/proof context. Neither
a nonzero digest nor a client-provided floor is sufficient authorization.
Persist final tombstone, verify exact retained digest, append collection/fence,
then remove only the latest-record view. Retain collection identity to reject
future replay; HTTP returns `TX_COLLECTED` with retained proof reference when
available. Expiry alone does not make a nonce cryptographically unspendable.

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

Proposed signed private-devnet host limits are 10,000 live/latest records,
256 MiB retained in-memory payloads, one active nonce/sender, 16 replacements
per sender/minute and 1 MiB proposal transaction payload budget. Mempool overload
returns `OVER_BUDGET`; it never evicts acknowledged durable intents. These are
local development settings; actual protocol block/resource caps take precedence.
If the installed protocol caps are absent, proposal construction is unavailable.
Candidate journal's stricter 100,000-frame/1 GiB/10,000-record bounds specified above remain
hard adapter ceilings. Payloads still count against retained journal bytes after
logical collection; capacity planning cannot assume physical compaction exists.

The host checks resource sums with overflow detection, charges the replacement
only for its incremental reservation after durable old/new resolution, and
reconstructs all reservations from recovered active records before opening RPC.
A balance change invalidates local eligibility, not an already finalized effect.

Limits cover transaction bytes, decoded nesting, signatures, state keys, read
and write declarations, proof work, gas dimensions, events, per-principal
entries, nonce gaps, replacements, global entries, retained bytes, WAL growth,
proposal bytes and readback work. Bounds are checked before allocation or
signature verification where possible. `u32::MAX` is not an operational count
limit.

## Security

The planned M14 error mapping uses `INVALID_ENCODING`, `WRONG_CHAIN`,
`INVALID_AUTHORIZATION`, `NONCE_REPLAY`, `REPLACEMENT_REJECTED`, `TX_EXPIRED`,
`OVER_BUDGET`, `NOT_FINALIZED`, `PROOF_UNAVAILABLE`, `RECOVERY_REQUIRED` and
`IO_UNCERTAIN`. Pure lifecycle/authorization rejection is not-applied; uncertain
journal/broadcast results carry `outcome:unknown` and exact tx ID. Retry the same
signed bytes after readback; never silently increment nonce. Stale predecessor
or receipt substitution stops that coordinator until source-bound recovery.

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

| Operation | Positive regression | Required negative / fault |
|---|---|---|
| Admit/retry | Exact tx and WAL sequence survive restart | Wrong chain/auth, expired intent, capacity exhaustion, duplicate JSON key |
| Replace | One CAS publishes old tombstone and new record | Concurrent proposal, lower/equal fee, crash at every pair publication cut |
| Broadcast | Permit, signer and durable peer receipt bind one envelope | Forged permit, lost ACK, altered receipt, unsupported signer |
| Execute/finalize | Ordered position and verified result agree | Other tx/root, nonzero fake proof, intermediate-root/block-root confusion |
| Collect | Authenticated finalized nonce floor fences replay | Client floor, floor equal to nonce, missing proof, collection crash |

Existing `production.rs` tests include
`admission_is_durable_before_ack_and_restart_recovers_exact_state`,
`replacement_every_commit_cut_and_lost_or_malformed_response_converges`,
`replacement_stale_predecessor_cannot_overwrite_concurrent_proposal`, and
`sign_broadcast_finalize_and_gc_are_durably_ordered`. They are port-level evidence;
networked proof/readback and external custody are separate integration tests.
Producers are M01 authorization, M02 order, M03 permit/signing, M06 execution,
M07 account state, M08 durable commit and M13 proofs. Consumers are M04 broadcast,
M14 API/SDK and M15 recovery. No consumer may treat admission as settlement.

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

### Candidate clock binding

For `native-public-candidate-v1`, capabilities bind `wall_clock_epoch_ms` to the
manifest/profile digest. Envelope validity fields and block time are milliseconds
since that epoch, despite the frozen envelope's `unix_ms` field names. The node
computes time using checked subtraction from its own Unix clock; clients cannot
supply the server time. SDK signing derives the same chain-relative value and
rejects a future epoch. Genesis remains canonical timestamp 0. M15 defines the
parent-relative step, skew readiness, empty catch-up and drain rules. An exact
retry returns its durable prior status even after expiry; recovery of an already
executed body verifies its historical block time and must not re-admit it using
a backdated clock.

### Candidate parent-header proof and batched finality

The ordinary public candidate proof response carries the exact canonical parent
header beside the unchanged `NativeTxProofPackageV1`. An independent consumer
pins its validator set, parameters and profile locally, decodes both headers,
checks chain/genesis/epoch/set/parameter scope and consecutive heights, and
requires the rehashed parent header ID to equal the target's signed `parent_id`.
Only then may it derive the timestamp used by the strict three-chain verifier;
a peer-supplied timestamp or `proof_verified` boolean is never authority. This
route remains ordinary same-epoch only; epoch-first targets require the separate
complete strict activation-evidence route. Native transaction hash remains
distinct from M05 intent ID. Combined package plus parent bytes stay within the
consumer's bounded proof budget.

The actual consensus owner archives transaction proofs at each completed native
finalization boundary. If one ingress batch or Core transition advances several
heights, it traverses the exact signed ancestor path from the current finalized
ID back to the last archived cut, reconstructs missing ordinary three-chains
from the existing durable proposal/QC archive, and reads each historical native
committed row against that proof. Missing ancestry, certificate or native row
stops progress with recovery required; no skipped height is marked archived.
Each proof is durable before the corresponding WAL handoff is committed.
