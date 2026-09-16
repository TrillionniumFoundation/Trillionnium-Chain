# M09 Data Availability technical specification v1

Status: candidate implementation contract; planned deployment profile below is
not a protocol activation. M09 owns bytes, commitments, retrieval and retention.
It does not own transaction validity, application roots or economic settlement.

## Authority

Read [DA protocol draft](../protocol/poco-ai-native-v1/06-certified-data-availability.md)
and [FullRep reference](../protocol/poco-ai-native-v1/da/DA_FULLREP_V1.md).
`trillionnium/crates/trnm-poco-da-v1/src/{types,codec,store,retrieval}.rs`
are the current candidate implementation. The local store supports
`TransactionBatch` namespace tag 0. `ArtifactEvidence` tag 1 is a distinct
protocol product and is unsupported by this store's namespace constructor.
Neither a full-replication certificate nor successful local read proves an
AI result correct. Erasure coding and sampling are outside this profile.

Candidate objects use strict Borsh decode/re-encode in `codec.rs`.
`digest_encoded` is SHA-256 of `u32_le(domain length) || ASCII domain || encoded`.
Use the exact source domain constants; do not hash JSON or transport framing.
Important domains include `trnm.poco-ai.da-batch.v1`,
`trnm.poco-ai.da-attestation-signature.v1`, and
`trnm.poco-ai.availability-certificate.v1`.
The candidate codec is not a frozen global CEV1 declaration or a CEV0 amendment.

## Interfaces

| Input / output | Exact binding and consumer |
|---|---|
| `ProtocolContextV1` | Genesis hash, chain ID and stack-profile hash; installed M00/M15 context |
| `DaCommitteeDescriptorV1` | Epoch, unique sorted members/keys/weights, retention and quotas; governance/validator projection supplies authority |
| `DaPolicyV1` | Exact committee ID, sorted authorized authors, batch/chunk/queue/retention limits |
| `UnsignedTransactionBatchV1` + `DaBatchAuthorV1` | Canonical transaction bytes, author, sequence and exact Ed25519 statement |
| `DurableAttestationIntentV1` | Store-created durable intent; M03 custody signs its exact root |
| `AvailabilityCertificateV1` | Envelope/author and matching sorted attestations; M02 requires certificate plus actual bytes before selected proposal validation |
| `VerifiedRetrievalProofV1` | Signed request/response and exact chunk reconstruction; repair consumes this capability |
| `DaObligationV1` | Retention liabilities used by M10/M11/M12/M13 and GC |

The certificate cannot choose its own committee. Resolve the descriptor from
authenticated epoch context before certificate admission. Distinct author,
committee and signer identities cannot be substituted merely because hashes
are nonzero. Peer authentication is M04's job; it does not replace DA signatures.

## Resource bounds

The deterministic replay fixture in `src/tests.rs::Fixture::new` uses four
members of weight 1, epoch 7, retention 2 epochs, author cap 8,192 bytes,
batch cap 4,096 bytes, 32 items, four outstanding sequences, 32-byte chunks,
256 chunks, retrieval window 50 blocks and repair window 20 blocks.
Its constructor-supplied queue count/bytes remain explicit test inputs.

For a planned networked development host select **DA-DEV-1**:

| Field | Selected value / admission rule |
|---|---|
| Namespace / replication | TransactionBatch / complete replication only |
| Committee | 4 unique authorized members, weights 1; threshold floor(2W/3)+1 = 3 |
| Batch / items / chunks | 4,096 bytes; 32 items; 32 bytes per chunk; at most 256 chunks |
| Outstanding author allowance | 4 sequences; 8,192 total retained bytes |
| Queue | 16 batches and 65,536 bytes, both independently enforced |
| Retention | 2 epochs; retrieval 50 blocks; repair 20 blocks; use larger applicable protocol liability |
| Network local controls | 4 concurrent retrievals per peer, 16 globally; 5-second request timeout; at most 2 retries |

These local host controls are planned and are not newly claimed source constants.
A signed commissioning manifest must contain exact chain/genesis/profile,
committee body and digest, epoch range, sorted member keys, author authorities
and sequence range, policy body/digest, store/scope IDs, custody references and
the above limits. Signatures are checked against independently installed M15
deployment keys, not keys supplied by the manifest itself.
Missing fields reject startup. Reopen must match all immutable identifiers.
Deviating from DA-DEV-1 requires another named authenticated profile and tests.
No deployment chooses a new quorum threshold independently of total weight.

## State machine

### `admit_batch`

1. Bound bytes/items/chunks before materializing nested collections.
2. Match installed context, epoch, namespace and author policy.
3. Recompute envelope, batch ID, content/chunk roots and author signing root.
4. Verify the authorized strict Ed25519 key; reject wrong sequence or conflict.
5. Reserve both author and global queue count/byte budgets atomically.
6. Persist exact content, manifest, envelope, author and obligation as `Stored`.
7. Commit and fresh-read the same record before returning admission.

Exact retry returns the same batch outcome without a second quota reservation.
Different bytes at the same author/scope/sequence are `SequenceConflict`.
No local admission consumes an application nonce or finalizes a transaction.

### `prepare_attestation` / `complete_attestation`

Before signing, audit the exact stored batch and required retention statement.
Persist the unsigned attestation and monotonic signer/sequence binding; only
then return `DurableAttestationIntentV1` and its signing root to custody.
Verify the returned signature/context/member binding, persist it and fresh-read
before releasing it. After response loss, replay the same durable intent.
Deleting the signed row cannot reset the high watermark or authorize another
statement at that conflict coordinate. A store checksum is not a signature.

### `admit_certificate`

Verify all attestations share exact context/namespace/epoch/envelope/retention.
Require sorted unique authorized members and keys; add weights with checked
arithmetic, charge every attempted signature verification, require at least
floor(2W/3)+1. Recompute certificate identity and install `Certified` with the
matching obligation. Under-quorum means invalid certificate, not missing data.
Exact certified batch and DA-head readback must come from one SQLite snapshot.

### Retrieval and repair

`prepare_full_range_retrieval_response_v1` consumes a signed full-range request
with requester authority, batch/certificate binding, time window and nonce.
Authenticate the request, enforce range and byte/work budgets, then read actual
chunks. The response signature binds that request, responder member, chunk
entries and exact receipt. `verify_full_range_retrieval_proof_v1` checks both
signatures, active membership, validity window, inclusion proofs, byte lengths,
ordering and complete reconstruction against the certified content root.

`repair_from_verified_retrieval_v1` consumes the verified proof, requires the
same retained batch/certificate and replaces only missing/corrupt local bytes.
It cannot rewrite the batch or borrow a foreign proof. Audit failure latches
`Unavailable`; exact verified repair may restore usable stored/certified data.
A request timeout is retryable local unavailability, not withholding guilt.

### Retention and GC

`extend_retention`/`release_retention` preserve the exact obligation identity.
Effective retention is the maximum of committee and all task/challenge/sync/
settlement holds; checked addition rejects overflow. A caller cannot shorten
another module's hold. Planned host integration authenticates each hold's owner,
operation ID, predecessor and finalized release receipt before invoking ports.

`garbage_collect` requires `FinalizedGcPermitV1` and exact obligation/checkpoint
readback. Its production permit issuer is not supplied by this local kernel.
Therefore automatic production deletion remains disabled. After permitted GC,
retain replay/sequence and attestation tombstones; state is `GarbageCollected`,
not a new empty batch. Collection must never enable reuse of an old sequence.

## Security

| Existing `DaErrorCodeV1` | Required response |
|---|---|
| `UnsupportedNamespace`, `InvalidContext`, `NonCanonical`, `IdentifierMismatch` | Reject without quota or state changes |
| `InvalidSignature`, `InvalidCommittee`, `InsufficientWeight`, `UnauthorizedAuthor` | Reject cryptographic/authority claim; charge attempted work |
| `SequenceConflict`, `Conflict`, `InvalidState` | Keep exact prior batch/sequence; never overwrite |
| `QuotaExceeded`, `QueueFull` | Local admission refusal; retain already accepted obligations |
| `InvalidRange`, `InvalidRepair`, `RetentionViolation`, `EarlyGarbageCollection` | Reject requested retrieval/repair/release; preserve retained bytes |
| `StoreFailure`, `NotFound` | Local unavailability; after possible write require fresh readback |
| `SchemaMismatch`, `TamperDetected` | Fence/audit recovery; no silent schema migration or fabricated empty state |
| `ArithmeticOverflow` | Deterministic rejection; no wrapping retention horizon or counters |

## Persistence and recovery

For loss before commit recover source; after commit recover exact target.
The current API uses `StoreFailure` rather than a new wire `Uncertain` code;
the owner must treat a failed mutating I/O as potentially applied and read back.
Open/reopen validates schema, metadata, all live rows, attestation inventory,
tombstones and accounting. Same-domain coherent rollback still needs independent
M03/M08 freshness. Never count a process test as power-loss qualification.

## Verification and evidence

| ID | Input and expected result |
|---|---|
| M09-Q3 | 4 members weight 1; 3 unique matching signatures certify; 2 return `InsufficientWeight` |
| M09-DUP | Repeat one signer in a 3-entry certificate: reject; weight cannot be counted twice |
| M09-SEQ | Author sequence s admits bytes A; retry A unchanged; bytes B at s return `SequenceConflict` |
| M09-CAP | 4,097-byte batch against 4,096 cap: reject before store reservation; 17th queued batch rejects under DA-DEV-1 |
| M09-SIGN-CUT | Crash after durable intent before signature response: recover exact intent and one logical signing coordinate |
| M09-REPAIR | Flip one stored chunk bit: audit unavailable; foreign proof rejects; exact signed full-range proof restores original certified bytes |
| M09-RETENTION | Hold ends at h=150; h=149 GC rejects; release needs authenticated hold-owner proof and finalized GC permit |
| M09-NAMESPACE | ArtifactEvidence certificate supplied for TransactionBatch: `UnsupportedNamespace`; no fallback |

Replay anchors in `src/tests.rs` include
`durable_before_attest_survives_reopen_and_rejects_bad_signature`,
`attestation_high_watermark_rejects_deleted_rows_and_sequence_reuse`,
`signed_full_range_retrieval_proof_repairs_exact_certified_bytes_and_reopens`,
and `certified_batch_and_da_head_share_one_fresh_sqlite_snapshot`.
These supply candidate source regressions; independent packet/byte vectors,
network interoperability and real storage/custody evidence remain acceptance work.
M02 reviews voting preconditions; M03 signing; M04 transport; M10-M13 retention.
The [DA case inventory](../protocol/poco-ai-native-v1/vectors/cev1-transaction-batch-da-kernel-v1.json)
identifies the current candidate corpus; its case names are not a complete
independently authored wire-vector set.

## Observability and SLO

Measure retained bytes/obligations per namespace, author/global queue pressure,
durable attestation latency, usable certified bytes, retrieval p50/p95/p99,
repair attempts, unavailable latches and retention/GC refusals. Certificate
count alone is not current retrievability. Under DA-DEV-1 report 0/1/5-percent
loss and 20/80/180-ms RTT runs with exact topology and sustained retention.
No bytes may be signed before durability or deleted before all holds close.

## Activation boundary

The local candidate lacks a production GC permit issuer and does not implement
ArtifactEvidence namespace. Network service, authenticated custody, externally
anchored rollback detection and actual retention/retrieval campaigns must be
implemented and accepted before corresponding deployment capabilities are enabled.
