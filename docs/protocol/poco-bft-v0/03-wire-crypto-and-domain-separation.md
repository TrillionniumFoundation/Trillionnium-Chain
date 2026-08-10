# 03 — Wire, Cryptography, and Domain Separation

## 1. Separation of logical schema and transport

The v0 signed and hashed representation is frozen. The bounded protobuf body
projection under `proto/trnm/poco/bft/v0` is the frozen v0 reference network
container; protobuf bytes are never signing bytes. Authenticated session
establishment, external stream framing, compression, RPC method layout, peer
discovery, and P2P multiplexing remain P2 implementation choices and MUST NOT
alter the decoded logical value or its limits.

A transport may use Protobuf or another bounded binary container, but it MUST decode to exactly the frozen logical fields and MUST reconstruct the same canonical `CEV0` bytes before hashing or signature verification. Transport bytes themselves MUST NOT be signed unless they are byte-for-byte `CEV0`.

Consensus objects have three distinct concepts:

1. a logical value with a frozen field order and types;
2. its single canonical `CEV0` encoding;
3. a domain-separated SHA-256 digest, which is the only value signed by Ed25519.

## 2. `CEV0` canonical encoding

`CEV0` is a schema-driven encoding. No field tags or self-description are added; the schema fixes order and type.

### 2.1 Primitive encodings

```text
u8, u16, u32, u64, u128  fixed width, unsigned, big-endian
bool                     one u8: 0x00 false or 0x01 true
Hash32                    exactly 32 bytes
PublicKey32               exactly 32 bytes
Signature64               exactly 64 bytes
FixedBytes<N>             exactly N bytes
Bytes                     u32 byte_length || raw bytes
ConsensusString           u16 byte_length || restricted ASCII bytes
Optional<T>               u8 tag (0 absent, 1 present) || T when present
List<T>                   u32 element_count || each T in sequence
Struct                    fields concatenated in the frozen schema order
Enum                      one u8 discriminant frozen by that schema
```

`ConsensusString` MUST match:

```text
[a-z0-9][a-z0-9._:-]{0,127}
```

It is used only for machine identifiers such as `chain_id` and domain labels. Human display text is not a consensus string. Opaque application identifiers are `Bytes` with schema-specific bounds.

`CEV0` forbids maps, sets without a prescribed sort order, signed integers, floating point, decimal text, varints, JSON numbers, implicit defaults, duplicate fields, unknown fields, and trailing bytes. A collection that is semantically a set MUST be sorted by the key required by its schema and MUST reject duplicates. Decoders MUST check configured length/count limits before allocation.

There is no alternate “equivalent” encoding. Non-canonical data is rejected rather than normalized.

## 3. Hash construction

Define:

```text
Frame(x) = u32_be(len(x)) || x
HASH_PREFIX = ASCII("trnm.cev0.hash.v0")
Digest(domain, logical_value) =
    SHA-256(
        Frame(HASH_PREFIX) ||
        Frame(ASCII(domain)) ||
        Frame(CEV0(logical_value))
    )
```

All lengths in `Frame` are byte lengths and MUST fit `u32`. `domain` MUST be one of the exact frozen lowercase ASCII strings in this document. Implementations MUST NOT add terminators, whitespace, Unicode normalization, or implementation-specific type names.

An Ed25519 consensus signature is the RFC 8032 Ed25519 signature over the resulting 32-byte `Digest`, not Ed25519ph and not a signature over hexadecimal text or raw transport bytes.

Verifiers MUST use strict Ed25519 verification: canonical encodings, canonical scalar `S`, valid curve points, and rejection of non-canonical or small-order public keys/points according to the selected audited library's strict mode.

## 4. Frozen domains

The exact v0 domains are:

```text
trnm.poco-bft.block.v0
trnm.poco-bft.proposal.v0
trnm.poco-bft.vote.v0
trnm.poco-bft.timeout.v0
trnm.poco-bft.qc.v0
trnm.poco-bft.tc.v0
trnm.poco-bft.handoff-descriptor.v0
trnm.poco-bft.handoff-vote.v0
trnm.poco-bft.handoff-certificate.v0
trnm.poco-bft.validator-set.v0
trnm.poco-bft.validator-key-pop.v0
trnm.poco-bft.parameters.v0
trnm.poco-bft.epoch-commitment.v0
trnm.poco-bft.upgrade-plan.v0
trnm.poco-bft.finality-proof.v0
trnm.poco-bft.double-sign-evidence.v0
trnm.poco-bft.ordered-leaf.v0
trnm.poco-bft.ordered-node.v0
trnm.poco-bft.ordered-root.v0
trnm.poco-bft.consumer-nonce-summary.v0
trnm.poco.consumption-certificate.v0
trnm.poco.consumption-certificate-id.v0
```

A domain change is a protocol-version change.

## 5. Common consensus context

Every signed consensus message begins with these logical fields in this order:

```text
schema_version          u16       // 0
genesis_hash            Hash32
chain_id                ConsensusString
protocol_version        u32       // 0 for this freeze
epoch                   u64
validator_set_hash      Hash32
view                    u64
message_kind            u8
```

`message_kind` discriminants are:

```text
0 proposal
1 vote
2 timeout
3 old_set_handoff_vote
4 new_set_handoff_vote
```

The domain and `message_kind` are both checked. A signature with a semantically mismatched pair is invalid.

Handoff messages additionally bind both old and new set hashes, both protocol versions, the transition descriptor, and the signer's role. The `validator_set_hash` in their common context is the set under which that particular signature's weight is counted.

## 6. Block header and block ID

The `BlockHeaderV0` field order is:

```text
schema_version                  u16
genesis_hash                    Hash32
chain_id                        ConsensusString
protocol_version                u32
epoch                           u64
view                            u64
height                          u64
block_kind                      u8
parent_block_id                 Hash32
proposer_id                     Bytes
active_validator_set_hash       Hash32
consensus_parameters_hash       Hash32
payload_root                    Hash32
state_root                      Hash32
receipts_root                   Hash32
evidence_root                   Hash32
timestamp_ms                    u64
next_epoch_commitment_hash      Optional<Hash32>
```

`block_kind` discriminants are:

```text
0 regular
1 epoch_checkpoint
2 epoch_seal_1
3 epoch_seal_2
4 epoch_handoff
```

The block ID is:

```text
Digest("trnm.poco-bft.block.v0", BlockHeaderV0)
```

The full block body contains the exact transaction-byte list and objective
evidence objects whose ordered roots match the header. `state_root` remains the
runtime/JMT authenticated-state root. The other three roots use the exact
algorithm below; no legacy Merkle helper, JSON/protobuf serialization, or
duplicate-last tree without a final leaf-count commitment is equivalent.

The header does not include its justify QC. Instead, the proposal signature binds the block ID and the exact certificate digests, preventing a leader from moving the same header between incompatible justifications.

### 6.1 Ordered payload, receipt, and evidence roots

`OrderedRootKindV0` discriminants are:

```text
0 payload
1 receipts
2 evidence
```

For an item at zero-based index `i`, its leaf digest is:

```text
OrderedLeafV0 =
    schema_version u16  // 0
    root_kind      u8
    index          u32
    item           Bytes

Digest("trnm.poco-bft.ordered-leaf.v0", OrderedLeafV0)
```

Leaves are paired left-to-right. At each layer, an odd final digest is paired
with itself. `level = 0` is the first layer above the leaves and increments by
one with checked `u32` arithmetic:

```text
OrderedNodeV0 =
    schema_version u16  // 0
    root_kind      u8
    level          u32
    left           Hash32
    right          Hash32

Digest("trnm.poco-bft.ordered-node.v0", OrderedNodeV0)
```

The final leaf or node is always wrapped by:

```text
OrderedRootV0 =
    schema_version u16  // 0
    root_kind      u8
    item_count     u32
    inner          Optional<Hash32>

Digest("trnm.poco-bft.ordered-root.v0", OrderedRootV0)
```

An empty list uses `item_count = 0` and `inner = None`; a nonempty list uses
its exact checked count and `Some(final_digest)`. The index in every leaf and
the count in the final wrapper are both mandatory. In particular,
`[a, b, c]` and `[a, b, c, c]` have different roots even though odd layers
duplicate their rightmost digest. Counts, indices, levels, item lengths, and
all allocation arithmetic MUST fit their frozen `u32` boundaries before work
begins.

The frozen empty roots are:

```text
payload   0165aeb0b26dc305d5d2a639f4d8ad56abd03fcf165af902d856ecf58eebced2
receipts  b455563b0b1e6ce49c079d2ef14e20dbccb1168af66d245d7295c45fa0895156
evidence  df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047
```

`application_payload` is the exact CEV0 `List<Bytes>` of transaction bytes in
execution order. It MUST decode canonically with no trailing data; validators
pass each raw item to the runtime without decode/re-encode before hashing.
The zero-transaction payload is the four bytes `00 00 00 00`, not an absent or
zero-length payload. `payload_root` is `OrderedRootV0(payload, tx_bytes)`.

Execution produces exactly one receipt per transaction at the same index.
`ExecutionReceiptCommitmentV0` has this exact CEV0 field order:

```text
schema_version       u16  // 0
transaction_index    u32
payload_leaf_hash    Hash32
gas_used             u64
fee_charged          u128
events               List<ExecutionEventV0>
```

`payload_leaf_hash` is the exact ordered-leaf digest for the transaction at
`transaction_index`. `ExecutionEventV0` is `kind: Bytes` followed by
`attributes: List<(key: Bytes, value: Bytes)>`. Kind, keys, and values are the
runtime strings' exact UTF-8 bytes. Event order is execution order;
attributes are strictly increasing by raw key bytes with no duplicates.
`receipts_root` is the receipts-kind ordered root over each exact receipt CEV0
value. The CEV0 `List<Bytes>` containing all receipt values MUST itself be no
larger than `max_block_bytes`; equality is accepted. Receipt bytes are derived
by execution and are not a second peer-supplied transport authority.

In protocol v0, a block's evidence list contains only exact
`DoubleVoteEvidenceV0` CEV0 values. Values are strictly ordered by their
recomputed evidence IDs with no duplicates; diagnostic proposal, timeout, or
handoff evidence is inadmissible until a later freeze assigns its canonical
ID schema. `evidence_root` is the evidence-kind ordered root over that list.

### 6.2 Host execution-validation boundary

The host result is local deterministic-core input, not a network object and
not a new CEV0 or protobuf value. Its classification is nevertheless
consensus-critical and has exactly these meanings:

- `Valid` requires a complete canonical `application_payload` whose ordered
  root equals the header's `payload_root`, an authenticated parent state whose
  root equals the parent header's `state_root`, the exact runtime/protocol
  version and parameters authorized for the epoch, successful deterministic
  execution, and exact equality of the computed `state_root`, `receipts_root`,
  and `evidence_root` with the header.
- `Unavailable` covers a missing or incomplete body, non-canonical body bytes,
  a source-supplied body whose ordered payload or evidence root differs from
  the corresponding header commitment, a missing or unauthenticated parent
  state, and transient runtime, database, or storage I/O. These facts identify
  a missing dependency or an unusable source, not a terminal property of the
  header. The node MUST permit bounded retry from another source.
- `DeterministicallyInvalid` is permitted only after the complete canonical
  body reproduces both its payload and evidence commitments, the parent state
  is authenticated, the authorized runtime and parameters are fixed, and all
  provenance and static invariants pass. It then means either that the frozen
  runtime-specific predicate classifies the complete block as terminally
  invalid, or that deterministic execution completes successfully but the
  computed state root or receipts root differs from the header. There is no
  deterministic evidence-root mismatch branch: source evidence-root mismatch
  remains `Unavailable`.

The production application stages exact `application_payload` decoding and
root derivation within authenticated `max_consensus_message_bytes`; that bound
keeps source parsing finite but is not a substitute for logical-block validity.
Only after the payload and evidence are canonical and reproduce their header
roots is the complete `logical_block_size_v0` compared with authenticated
`max_block_bytes`; excess at that point is `DeterministicallyInvalid`.

After body authorization, any root/hash computation failure or payload,
evidence, static-commitment, `BlockId`, provenance, or other internal drift is
an invariant/fail-stop condition. It MUST NOT be downgraded into either
`Unavailable` or `DeterministicallyInvalid`.

Transaction execution failure is not implicitly a failed receipt. A runtime
profile may keep the block valid and commit a failed-transaction receipt only
if that profile freezes the exact deterministic failure predicate, state
transition, gas/fee accounting, events, and canonical receipt outcome. The
current `ExecutionReceiptCommitmentV0` has no outcome/status field. The active
Trillionnium v0 runtime profile therefore permits successful receipts only:

- each of its 21 typed deterministic transaction rejects makes the complete
  authenticated block `DeterministicallyInvalid` and produces no receipt,
  mutation, nonce, fee, gas event, or other partial execution artifact;
- each of its 7 typed authenticated-state or internal invariant faults requires
  host fail-stop and MUST NOT be projected as a transaction reject;
- missing body/parent/cutoff dependencies and transient runtime, database, or
  storage failures remain `Unavailable` and MUST NOT be inferred from runtime
  diagnostic text.

The runtime taxonomy is exhaustive and opaque to callers, but that leaf policy
does not itself authenticate the body, parent state, cutoff, runtime context or
computed roots. The bounded Rust seam now reflects that provenance rule:
`TryStateViewV0`/`try_execute_v0` preserves a typed state-read failure and
returns an opaque real-attempt failure with no public constructor. Its
module-private, still-unwired application adapter consumes the authenticated
execution-input token into the real call and retains that same token in either
result, so promotion cannot splice a second same-generation join. It does not
terminalize a typed state failure; it promotes only the deterministic branch
carried by that attempt. A successful call produces an applied attempt rather
than `Valid`, and a
separate exact roots-match capability must own that applied attempt before
`Valid` can be formed.

The bounded store slice now has a typed self-head reader plus an opaque runtime
snapshot that owns one SQLite `Connection`. Inside one `BEGIN` transaction it
validates configured bindings, canonical committed height and app hash, query
floor, latest authenticated-root version, and equality of the head root with
the app hash. Multiple object/non-membership reads therefore share one
snapshot; an explicit typed `finish` ends it, and begin uses maintenance
`try_lock` rather than waiting behind maintenance. Core now privately freezes
the exact positive-height parent header in the payload-validation request, and
the store consumes that capability to open only an exact committed-head
height/root. Synthetic genesis is explicitly headerless; speculative/non-head
parents are retryable source mismatch until a canonical overlay store exists.
This is bounded validation-parent authority, not a general host/ABCI runtime-
view adapter. The bounded production validation cursor owns a private fallible
`prior delta -> exact authenticated snapshot` view, while legacy `load_object`
continues to use its direct-read path and no ABCI outcome consumes that view.

A separate legacy test-only inert regular-block traversal owns the exact compared
header/body/configuration and that one parent-bound snapshot. Its only cursor
derives raw outer transaction bytes, index, target height, and target
`BlockId` from the retained body/header, in order; callers cannot inject an
index or transaction. The same snapshot authenticates the validator-lifecycle
record and physical singleton and joins its active projection to the retained
native set. It yields a finished inert value only after the complete
body was traversed and the snapshot finished successfully. A cursor
classification is obtained only by explicitly finishing the consumed
traversal, whose errors outrank both incomplete traversal and cursor rejection;
Drop yields neither classification nor capability. From each exact outer byte string it now
decodes `SignedCommandEnvelopeV1`; the consensus-app-specific helper applies
dalek `verify_strict` plus the existing chain and
header-time checks against the exact store-bound signer list, then decodes the
exact inner payload as `CanonicalTxV1` and joins payload type, sender and nonce.
The raw outer and inner bytes remain the committed facts; decoded values are
not reserialized into authority. Signer-policy admission now exact-decodes the
Ed25519 point and rejects weak keys. This tightening does not alter generic
`verify_hex`, vote/QC languages, the live-node development oracle, or instantiate
the PoCO `StrictEd25519Verifier` type; retained production history would require
an explicit activation boundary.

A distinct legacy test-only owning runtime session consumes that same exact joined
input and snapshot. Its runtime `ExecutionContext` is derived internally from
the retained header/envelope, transactions can only execute in body order, and
the real `try_execute_v0` reads `session changes -> fixed parent snapshot`.
Successful runtime receipts are translated to native receipt shape only. Their
mutation sets are applied first to a cloned delta and accepted only after an
exhaustive account/task/fee/monetary canonical key/type/value check plus
unique-key, immutable-type, expected-version, and exact-successor checks.
Task mutations additionally reuse the runtime's full status/field-group/
version/height validator through a distinct opaque read-only failure type.
Consequently a later transaction can see an earlier private delta, while a
later cursor/runtime/state/receipt/mutation failure consumes the whole session
and exposes neither earlier changes nor receipts. Both the successful and
failed session require explicit snapshot finish; a finish error has priority
over the pending cause.
After a failed snapshot finishes, one opaque non-cloneable value still owns the
exact block/configuration inputs, authenticated lifecycle, failed index, and
decoded observation/transaction together with the hidden cause. It accepts no
second input join and exposes no standalone cause.

The successful legacy test-only path now plans post-state without reopening the
database: it fully revalidates the fixed parent on the same SQLite transaction,
encodes the complete private delta, and derives only the exact `parent + 1` JMT
plan. Planning and completeness remain inert until explicit snapshot finish.
The resulting whole value is then consumed by a comparator which reconstructs
native receipts from the retained raw body and real runtime receipts, uses the
hard-coded `StrictEd25519Verifier`, and exact-compares the four header roots,
configuration, and `BlockId`. The planner is query-only, applies no writes, and
the positive fixture independently authors its expected state root from an
in-memory parent tree rather than asking the comparator for one. A same-path
independent WAL writer test commits a competing sibling after the first
runtime read and proves that later reads and planning stay on the original
parent snapshot until explicit finish.

This preceding legacy test-only session and its finished-plan/root-matched
values are not wire objects or terminal authority. They have no production
constructor, serialization, or conversion to a terminal execution outcome,
`AuthorizedNativeCheckpointExecutionV0`, checkpoint, Core, or ABCI. A separate
bounded production cursor below now supplies process-local planning and
four-root comparison with the same non-authority boundary. JMT plan
application/persistence, non-runtime dispatcher families, matched/mismatch
terminal promotion, and host/Core/ABCI callback wiring remain open. The Core transport holder now
matches the frozen proto projection exactly: one header, one complete
`ApplicationPayloadV0` CEV0 value, and ordered complete evidence-object CEV0
values. Core alone constructs an opaque validation request over that retained
block and its exact positive-height parent. A narrow app carrier consumes that
request, opens the exact committed parent AppHash/JMT snapshot, loads and proves
the complete namespace-8 active validator set and parameters plus lifecycle on
that same SQLite transaction, and joins their epoch/hashes to the header before
staged exact-decoding of the payload under authenticated
`max_consensus_message_bytes` and exact-decoding every evidence object. It
binds both peer-body roots before strict Ed25519 evidence verification and the
complete logical-block `max_block_bytes` classification. Source root mismatch
remains `Unavailable`; canonical root-bound logical oversize is
`DeterministicallyInvalid`. This carrier is process-local comparison authority, not a second
transport/configuration language; it has no serialization, caller-supplied
height/root/set/parameters, cache, or second connection. It grants no runtime,
terminal-result, vote, finality, checkpoint, or ABCI authority.

Before that admission succeeds, the exact Core request remains inside a
private process-local owner. A host failure before snapshot begin returns that
owner directly. Once a snapshot is open, source or body-admission failure can
escape only after close and still owns the exact `ValidationId`, target block,
and parent. It does not own an authorized body and cannot be recreated from a
transported ID, generation, block, parent, or cause. If close fails, the typed
snapshot failure replaces the pending source/invalid/invariant cause while the
exact Core owner remains. These are ownership and error-precedence rules, not
an added wire encoding or peer-visible failure object.

The original Core-issued `PayloadValidationRequest` and every `Clone` descended
from that object graph share one process-local Arc-backed atomic one-shot gate.
Exactly one claimant in the graph can enter the owning validation path. A
losing clone is suppressed/coalesced by the current private native-admission
branch before snapshot open and before source, deterministic-invalid, or
invariant classification; that branch emits neither a classification nor a
callback for it. This is not a wire-visible result and not full-`ValidationId`
process uniqueness. Independently started Cores from the same obligation-free
durable state may accept the same ingress and materialize separate request/gate
object graphs; public Core `Input` is not a capability callback. A different
generation has an independent gate, while an old object graph remains
suppressed after its one claim. The gate is not encoded on the wire and by
itself makes no cross-instance, durable, or cross-restart exactly-once promise.

The request also carries a Core-private binding to
`PayloadValidationRouteV0::Proposal` or `PayloadValidationRouteV0::Synced`.
Native admission consumes the entire Core `Effect` and verifies the outer
`ValidatePayload`/`ValidateSyncedPayload` wrapper against that inner route
before the object-graph claim or any host read. A wrapper splice is a local
transport invariant, does not consume the correctly wrapped clone, and is not
a duplicate, `Unavailable`, or `DeterministicallyInvalid` wire result. The
route remains inside the owner across open/body/cursor/runtime/post-state/
comparator/disposition; no naked bool or route is accepted as authority.

Separately from application-store schema v7, Core `SafetyState` schema v5
introduced a canonically ordered `DurablePayloadValidationObligationV0` before
either validation effect may escape a `PersistSafetyState -> StorageAck`
barrier. This cloneable persistence fact binds the Core-selected route, full
`ValidationId`, exact `SignedProposalV0`, exact
`PayloadValidationParentV0`, and `first_recorded_revision`; the live invariant
also binds generation to that revision. It is not a wire object, terminal
token, or callback capability. `StorageAck` reconstructs the request only from
that record and its exact volatile proposal mirror. Core `SafetyState` schema
v6 adds a separately canonically sorted
`DurablePayloadValidationCompletionV0` keyed by `(route, full ValidationId)`.
Every callback atomically replaces its exact obligation with the same-key
completion before persistence. This cloneable local persistence fact retains
all three results, complete `ValidatedBlockCommitmentsV0` for `Valid`, and
`first_recorded_revision`; exact same-result replay is durably idempotent after
restart. Opposite-route reuse, a source/owner splice, different results, or
different `Valid` commitments is invariant or a typed integration conflict,
never a replacement. `Unavailable` closes only that generation and does not
poison a later generation for the same block. These records are distinct from
the block-ID-level terminal payload facts, which retain cross-generation
`Valid`/`DeterministicallyInvalid` semantics. Exact synced cancellation removes
the obligation behind the cleanup barrier without inventing a callback
completion. Safety halt clears obligations while retaining prior completions.
There is no automatic completion eviction: registration reserves the future
slot and `completions + obligations` is bounded by authenticated
`max_observed_messages`. Complete signed-proposal durable size -- logical block
plus exact certified-tail witness -- is bounded by authenticated
`max_consensus_message_bytes`; aggregate obligation accounting additionally
covers fixed route/ID/revision/parent facts and an optional exact parent header.

Recovery validates schema-v6 obligations and completions and then rejects a
non-empty obligation set with `InvalidRecovery`; it does not reissue pending
validation. Safety-state schema v5 has no implicit migration. Completion-only
recovery supplies exact-result suppression, but these local persistence rules
establish no new transport, type-level callback capability, crash replay/
liveness, host-delivery acknowledgement, or callback exactly-once protocol.

Historical application-store schema v6 adds local `validation_jobs_v0` and
`validation_callback_outbox_v0` relations; neither is a wire type or peer
authority. Before any host/snapshot read, one `BEGIN IMMEDIATE` transaction
stores the route/full ID, exact target header, a strict versioned raw body
record, parent tip and optional exact parent header/state root, configuration
references, the currently generation-derived creation revision, the existing
source fingerprint, and distinct domain-separated body/immutable/row
checksums. Its only active state is `reserved`; v6 rejects every non-reserved
row and every non-empty outbox.

Application-store schema v7 preserves those reserved rows and activates one
narrow terminal persistence case: `callback_pending`
`DeterministicallyInvalid` for the complete mixed-body comparator's computed
state-root or computed receipts-root mismatch. A fixed canonical artifact binds
the route, full `ValidationId`, raw-request fingerprint, immutable-job
checksum, result tag, and closed reason code. A fixed callback payload binds
the same route/full ID and result to the artifact checksum. Distinct hashes
bind the artifact bytes, callback payload bytes, callback idempotency identity,
and complete outbox row. One `BEGIN IMMEDIATE` transaction stores the artifact,
inserts exactly one congruent outbox row, moves the job from `reserved` to
`callback_pending`, and updates accounting; no committed intermediate
`evaluated` state is valid. Exact retry returns the existing row without
double-accounting. Every other invalid reason, `Valid`, `Unavailable`,
`InvariantFault`, `evaluated`, `delivered`, `acked`, and `applied` remains
inactive and fail closed in v7.

Exact reopen returns verified durable state without reminting first-evaluation
authority. Startup/recovery exact-decodes and canonically re-encodes the target
and any present parent header, rebinds identity/parent/configuration fields,
rederives the raw-source fingerprint, and validates the job, artifact, outbox,
checksums, and canonical row order. The journal is capped at 65,536 rows plus a
512-MiB raw-request budget, with separate bounded artifact/outbox accounting
and an atomic O(1) accounting singleton independently audited at startup. The
app accepts only parameter profiles with `max_block_bytes <= 16 MiB`. Empty
schema v5 journals migrate through reserved-only v6 into v7; non-empty v5
reservations fail closed and remain byte-for-byte intact, and corrupt v6
activation rolls back atomically. State sync deletes outbox then jobs only from
the temporary copy and verifies both are empty. These facts are
corruption/congruence seals and durable callback intent only, never
signed-proposal reconstruction, Core callback authority, delivery,
acknowledgement, takeover, or exactly-once authority.

The exact process-local integrity labels used by this foundation are:

```text
trnm.native-validation-reservation.hash.v0          // raw SHA-256 prefix
trnm.consensus-app.native-validation-reservation.v0 // raw framed fingerprint domain
trnm.consensus-app.validation-body.v0               // hash_domain
trnm.consensus-app.validation-job-immutable.v0      // hash_domain
trnm.consensus-app.validation-job-row.v0            // hash_domain
trnm.consensus-app.validation-runtime-profile.v0    // hash_domain
trnm.consensus-app.validation-host-config.v0        // hash_domain
trnm.consensus-app.validation-artifact.v0           // hash_domain
trnm.consensus-app.validation-callback-payload.v0   // hash_domain
trnm.consensus-app.validation-callback-idempotency.v0 // hash_domain
trnm.consensus-app.validation-callback-outbox-row.v0  // hash_domain
```

These are node-local integrity/congruence labels, not consensus signature or
wire-object domains. The v7 artifact and callback records use the fixed codec
labels `trnm.native-validation.invalid-artifact.v0` and
`trnm.native-validation.invalid-callback.v0`; both remain application-local
inert records and introduce no peer-visible result or signing domain.

The invalid-artifact v0 record is exactly 120 bytes: big-endian `u16` codec
version zero, one-byte route, 32-byte block ID, big-endian `u64` view and
generation, 32-byte request fingerprint, 32-byte immutable-job checksum,
one-byte deterministic-invalid result tag, and big-endian `u32` reason. Reason
zero is unassigned; one means computed state-root mismatch and two means
computed receipts-root mismatch. The invalid-callback v0 record is exactly 84
bytes: version, route, block ID, view, generation, the same result tag, and the
32-byte artifact checksum in that order. Decoders require the exact size,
known version/route/result/reason, strict EOF, and byte-identical canonical
re-encoding.

The same process-local carrier may now borrow the canonical signer-policy
preimage only from initialized `AppCore`, after its commitment matches store
metadata and the authenticated lifecycle in that exact snapshot. Its
sequential cursor selects the retained body index internally, strictly verifies
the exact envelope, exact-decodes and validates the inner `CanonicalTxV1`,
joins sender/nonce, and derives height, native `BlockId`, header time, signer
id/role, and exact inner-byte length. The prepared transaction still owns the
cursor and snapshot. It is not a second transaction/configuration transport and
has no seek/repeat/skip, parts conversion, or caller-supplied
tx/index/context/view. One consuming attempt executes the real fallible runtime
over `prior delta -> that same snapshot`; only native-receipt conversion and
atomic full-mutation staging may return the cursor at `index + 1`. Failures
retain the exact authorized owner and stage facts until finish: decode close
retains next index, private delta, and applied receipts, while runtime close
retains failed index, exact outer/inner bytes, decoded transaction, and derived
context after intentionally destroying prior delta/receipts. Finish failure
replaces the pending stage cause without discarding that owner, and none mints
terminal-result, vote, finality, checkpoint, or ABCI authority. Non-runtime
payloads retain the exact bytes, verified envelope/context, cursor, and
snapshot in an opaque routing carrier rather than becoming an invented invalid
result or advancing the index.

For a complete runtime-only body, the same process-local cursor replays every
retained real `RuntimeReceipt` mutation set separately and sequentially against
that authenticated snapshot. Reusing a key across transactions is legal only
when expected/next object versions form one continuous chain; duplicate keys
within a single receipt are invalid. The replayed final map must exactly equal
the cursor's canonical private delta, and only that map can supply writes to
the unique exact-next JMT plan. An opaque process-local seal covers that plan's
exact version, root, nodes, values, stale-node indices, and key preimages. The
snapshot closes before the sealed inert finished plan escapes. Planning,
replay, read, or completeness failure instead closes with the authorized owner,
next index, private delta, and applied receipts. If snapshot finish fails, its
cause replaces the pending plan cause and any computed plan/seal is discarded,
without losing the exact owner. A single consuming comparator rebinds retained
receipt -> replayed delta -> exact plan,
verifies the full seal before any root mismatch, rebuilds native receipts, and
hard-codes strict Ed25519 for ordinary static commitments. Root/hash
computation, seal, or other post-authorization payload/evidence, static-
commitment, `BlockId`, provenance, or internal drift is invariant/fail-stop.
Its process-local owning result can classify only `Valid`,
`DeterministicallyInvalid(State|Receipts)`, or `InvariantFault`; every branch
retains the complete owner. `SourceUnavailable` is structurally excluded by the
earlier source-admission boundary. These values are neither a new wire language
nor a terminal result. All corresponding pre-terminal failure carriers are
private, non-cloneable, non-serializable, have no `From`/`TryFrom`, parts, or
standalone-cause escape, and accept no second generation or authority join.

Snapshot begin does not repeat the startup full-table sweep for future orphan
values/nodes or stale-index rows. Its in-memory pin protects only handles in
one cloned `ApplicationStore` family, not an independently opened handle or
another process; no external rollback watermark or OS-level process lock has
landed. This bounded seam is not the complete production host adapter. The
Core-issued request and same-snapshot join now freeze the exact `BlockId`, peer
body, positive-height parent, committed-head active configuration, exact
transaction decode/index/context, runtime-gated success-only advance, same-
snapshot complete-body JMT planning, and four-root comparison.
Synthetic genesis authority, speculative-parent storage, complete-body JMT
plan application/state persistence and head update, final typed retryable-
versus-invariant host mapping, a private route-aware callback adapter,
host/Core callback wiring, ABCI wiring, non-runtime routing, and promotion of
the owning classifications into
`ExecutionOutcomeV0` or other terminal authority remain hard gaps before a
terminal/Core callback path. The object-graph gate itself performs no terminal
mapping; only the current private admission branch is proven to emit no
callback for a losing clone.
The route-bearing disposition likewise is not a terminal result and invokes no
Core `Input` or ABCI operation. A narrow consuming bridge may prepare only the
complete-body state-root or receipts-root deterministic mismatch for the v7
application-store transaction; it cannot prepare `Valid`, `Unavailable`, or an
invariant fault. Schema v7 atomically couples that canonical invalid artifact
with callback-outbox intent, but it does not call `Core::step` or deliver the
intent. A future delivery bridge must map `Proposal` only to
`PayloadValidated` and `Synced` only to `SyncedPayloadValidated`. The `Valid`
validation-time artifact/outbox boundary remains open. The distinct Finalize-
time atomic boundary still must revalidate exact authority and atomically
couple JMT/domain apply, root/native-head persistence, head advancement, and
applied state. Core's completed cleanup `StorageAck` and completion tombstone
are not a host callback-outbox delivery acknowledgement.
Authenticated replay tickets, completion retirement after a durable
host-delivery acknowledgement, speculative-parent/
BlockTree reconstruction, application-reservation takeover, `Valid` evaluated-
artifact persistence, host callback-outbox scheduling/delivery acknowledgement,
crash takeover, Core callback delivery, ABCI, the `Valid` validation-time and
Finalize-time atomic boundaries, and process-wide callback exactly-once remain
absent.
Runtime
resource estimation now has a distinct `try_estimate_resources_v0` call and
opaque estimate-failure token: state dependency errors remain typed,
deterministic failures do not arise from diagnostic text, and estimation
cannot return a receipt or mutations. That type is deliberately distinct from
the real-execution attempt token. The legacy infallible estimator remains the
only application caller, so the fallible estimator has no consensus-admission
authority yet. Historical cutoff/projection reads still use their legacy error
boundary; the exact estimate-input carrier, terminal native carriers, and
ABCI/host integration also remain open.
Protocol v0 drivers MUST NOT invent failed receipts or choose a different
classification per implementation. ABCI `ProcessProposal` has no faithful
`Unavailable` status; mapping retry to either `REJECT` or `UNKNOWN` is non-
conforming.

## 7. Proposal signing value

`ProposalSignV0` is:

```text
context                         CommonConsensusContext
height                          u64
block_id                        Hash32
justify_qc_digest               Hash32
timeout_certificate_digest      Optional<Hash32>
handoff_certificate_digest      Optional<Hash32>
```

The proposer signs:

```text
Digest("trnm.poco-bft.proposal.v0", ProposalSignV0)
```

The context view MUST equal the block-header view. The context set hash MUST equal the block's active set hash.

`justify_qc_digest` always names the exact ordinary or context-authorized
synthetic QC carried by the proposal. Optional certificate presence is
canonical: an absent object has an absent digest and a present object has a
present digest equal to the object's canonical digest. For a first
non-genesis-epoch proposal, `handoff_certificate_digest` is exactly
`authorization.handoff_certificate.id()`. The complete
`EpochAnchorAuthorizationV0` MUST be present and verify atomically; the
authorization itself has no separate digest domain, and a bare peer-supplied
certificate digest is not an authorization.

The transport presence matrix is:

| Proposal class | `justify_qc` | timeout certificate | epoch-anchor authorization |
| --- | --- | --- | --- |
| ordinary, next view | signed ordinary parent QC | absent | absent |
| ordinary, skipped view | TC-selected signed ordinary parent QC | present | absent |
| genesis first block, view 1 | exact trusted `GenesisQC` | absent | absent |
| genesis first block, view > 1 | exact trusted `GenesisQC` | present and selects `GenesisQC` | absent |
| epoch first block, view 1 | exact authorized `EpochAnchorQC` | absent | required |
| epoch first block, view > 1 | exact authorized `EpochAnchorQC` | present and selects `EpochAnchorQC` | required |

A synthetic QC is invalid in every other proposal position.

## 8. Vote and QC values

`VoteSignV0` is:

```text
context              CommonConsensusContext  // message_kind = 1
height               u64
block_id             Hash32
```

The validator signs:

```text
Digest("trnm.poco-bft.vote.v0", VoteSignV0)
```

`QuorumCertificateV0` field order is:

```text
schema_version       u16
genesis_hash         Hash32
chain_id             ConsensusString
protocol_version     u32
epoch                u64
validator_set_hash   Hash32
view                 u64
height               u64
block_id              Hash32
signatures           List<(validator_id: Bytes, signature: Signature64)>
```

`signatures` MUST be strictly ordered by `validator_id`. Each signature verifies the reconstructed `VoteSignV0`. The QC digest is:

```text
Digest("trnm.poco-bft.qc.v0", QuorumCertificateV0)
```

The claimed total weight is deliberately absent from the canonical QC. It is always recomputed.

### 8.1 Context-authorized synthetic QCs

Synthetic anchors use the exact `QuorumCertificateV0` CEV0 schema and the
existing QC domain, with an empty signatures list. They do not add a kind byte
and do not change any ordinary QC digest.

The trusted genesis document reconstructs exactly one `GenesisQC`:

```text
schema_version       u16 = 0
genesis_hash         Hash32
chain_id             ConsensusString
protocol_version     u32 = 0
epoch                u64 = 0
validator_set_hash   Hash32 = epoch-0 set hash
view                 u64 = 0
height               u64 = 0
block_id              Hash32 = genesis_hash
signatures            List<SignatureShare> = empty
```

The synthetic genesis block has no `BlockHeaderV0`; its canonical block ID is
exactly `genesis_hash`. The `GenesisQC` digest is
`Digest("trnm.poco-bft.qc.v0", GenesisQCV0)`.

A verified joint handoff reconstructs exactly one `EpochAnchorQC`:

```text
schema_version       u16 = 0
genesis_hash         Hash32
chain_id             ConsensusString
protocol_version     u32 = new_protocol_version
epoch                u64 = new_epoch
validator_set_hash   Hash32 = new_validator_set_hash
view                 u64 = 0
height               u64 = terminal_old_height
block_id              Hash32 = terminal_old_block_id
signatures            List<SignatureShare> = empty
```

Its digest uses the same QC domain. `EpochAnchorAuthorizationV0` is the
following nested logical value and has no independent hash domain:

```text
terminal_old_header       BlockHeaderV0
terminal_old_qc           QuorumCertificateV0
handoff_certificate       HandoffCertificateV0
```

The terminal QC MUST certify the exact terminal header and match the
descriptor's terminal digest. The descriptor, checkpoint/seals, independent
old/new quorums, sets, parameters, versions, and activation height MUST all
verify before the epoch anchor is reconstructed.

An empty-signature QC is accepted only when it byte-for-byte matches the
trusted genesis anchor or a locally verified epoch-anchor authorization. It is
never an ordinary standalone QC, never certifies a block, and is never a
certifying QC in a finality proof. A proposal or TC may carry the exact anchor
QC for reconstruction, but peer transport alone grants it no authority.

## 9. Timeout and TC values

`HighQCSummaryV0` is:

```text
qc_digest           Hash32
qc_epoch            u64
qc_view             u64
qc_height           u64
qc_block_id         Hash32
```

`TimeoutSignV0` is:

```text
context             CommonConsensusContext  // message_kind = 2
high_qc             HighQCSummaryV0
```

The timeout signature is over:

```text
Digest("trnm.poco-bft.timeout.v0", TimeoutSignV0)
```

`TimeoutEntryV0` contains the signer ID, `HighQCSummaryV0`, and signature. `TimeoutCertificateV0` contains:

```text
schema_version              u16
genesis_hash                Hash32
chain_id                    ConsensusString
protocol_version            u32
epoch                       u64
validator_set_hash          Hash32
timed_out_view              u64
entries                     List<TimeoutEntryV0>
referenced_qcs              List<QuorumCertificateV0>
selected_high_qc_digest     Hash32
```

Entries are strictly ordered by signer ID. Referenced QCs are deduplicated and
strictly ordered by QC digest. Every entry's summary MUST match one included
valid signed QC or the one context-authorized view-0 synthetic anchor, and
every included reference MUST be named by at least one counted entry; unused
references invalidate the TC. The number of entries cannot exceed the active
validator count and the number of references cannot exceed the entry count.
More than one QC MAY have the same `(view, block_id)` when its
canonical signature subset, and therefore its digest, differs. The selected
digest MUST name the unique maximum included QC referenced by a counted entry
under `(view, block_id, qc_digest)`. Two QCs at the same epoch/view with
different block IDs remain a safety-assumption violation and invalidate the
TC. A single block ID bound to different `(epoch, view, height)` coordinates,
or a single `(epoch, view)` bound to different `(height, block_id)`
coordinates, also invalidates it. The TC digest is:

```text
Digest("trnm.poco-bft.tc.v0", TimeoutCertificateV0)
```

Equivalently, let `E` be the set of `high_qc.qc_digest` values in all counted
entries and `R` the digest sequence of `referenced_qcs`. Canonical validation
requires `R` to be strictly increasing and `set(R) = E`. Missing references,
unreferenced extras, duplicates, and reordering are invalid and MUST NOT be
normalized away. A synthetic anchor participates in the same equality rule;
its authorization sidecar is verified separately and is not an extra
reference.

## 10. Validator-set commitment

`ValidatorV0` is:

```text
validator_id          Bytes
consensus_public_key  PublicKey32
effective_weight      u64
```

`ValidatorSetV0` is:

```text
schema_version             u16
genesis_hash               Hash32
chain_id                   ConsensusString
protocol_version           u32
epoch                      u64
consensus_parameters_hash  Hash32
validators                 List<ValidatorV0>
```

Validators are strictly ordered by `validator_id`; IDs and keys are unique;
every ID is nonempty and no longer than both the active committed
`max_validator_id_bytes` and the v0 hard maximum of 128 bytes; every effective
weight is positive. The chain ID is similarly nonempty and no longer than
both `max_chain_id_bytes` and 128 bytes. P2P endpoints, display names,
commission data, and operator metadata are not consensus-set fields.

The validator-set hash is:

```text
Digest("trnm.poco-bft.validator-set.v0", ValidatorSetV0)
```

## 11. Parameter commitment

`ConsensusParametersV0` has this exact field order:

```text
schema_version                              u16
protocol_version                            u32
production_activation                       bool
max_chain_id_bytes                          u16
max_validator_id_bytes                      u16
max_block_bytes                             u32
max_consensus_message_bytes                 u32
min_validators                              u32
max_validators                              u32
quorum_numerator                            u32
quorum_denominator                          u32
quorum_addend                               u32
finality_certified_chain_length             u8
max_total_voting_power                      u64
max_block_time_step_ms                      u64
leader_schedule                             u8
require_full_payload_before_vote            bool
base_timeout_ms                             u64
timeout_multiplier_numerator                u32
timeout_multiplier_denominator              u32
timeout_max_ms                              u64
epoch_length_blocks                         u64
epoch_seal_blocks                           u8
snapshot_lead_blocks                        u64
joint_handoff_old_quorum                    bool
joint_handoff_new_quorum                    bool
upgrade_notice_epochs                       u64
max_protocol_version_jump                   u32
scale_ppm                                   u64
maturity_epochs                             u64
max_certificate_age_epochs                  u64
decay_step_ppm_per_epoch                    u64
per_certificate_unit_cap                    u128
per_consumer_provider_epoch_unit_cap        u128
per_task_provider_epoch_unit_cap            u128
per_provider_epoch_unit_cap                 u128
units_per_power                             u128
bond_atomic_units_per_power                 u128
min_validator_power                         u64
max_validator_power                         u64
max_validator_share_ppm                     u64
capped_weight_alpha_ppm                     u64
full_weight_alpha_ppm                       u64
rollout_phase                               u8
minimum_shadow_epochs                       u64
minimum_eligibility_only_epochs             u64
minimum_capped_weight_epochs                u64
automatic_promotion                         bool
evidence_window_epochs                      u64
unbonding_delay_epochs                      u64
jail_duration_epochs                        u64
trusting_period_epochs                      u64
require_trusting_period_less_than_evidence  bool
require_evidence_window_le_unbonding_delay  bool
```

Enum values are:

```text
leader_schedule: 0 = canonical-validator-round-robin
rollout_phase:   0 = shadow, 1 = eligibility-only,
                 2 = capped-weight, 3 = full
```

The fixed `CEV0`/SHA-256/Ed25519 choices are protocol-version constants, not negotiable parameters. TOML keys `schema`, `profile`, string descriptions, comments, and the entire `[status]` table are not part of `ConsensusParametersV0`. Every remaining numeric/boolean TOML value maps once to the field above; a missing, duplicate, out-of-range, unknown-enum, or semantically inconsistent value makes the parameter set invalid.

The snapshot schedule is a cross-field validity rule, not a profile hint:
`snapshot_lead_blocks` MUST be at least
`finality_certified_chain_length`. Protocol v0 fixes the latter to `3`, so
lead values `0`, `1`, and `2` are invalid. Independently,
`epoch_length_blocks` MUST be greater than
`snapshot_lead_blocks + epoch_seal_blocks`. Both the old and candidate
parameter preimages are checked before an epoch commitment can satisfy the
same-version context relation.

Its hash is:

```text
Digest("trnm.poco-bft.parameters.v0", ConsensusParametersV0)
```

P0 freezes the logical value, not a transport generator. The independent
reference encoder and committed parameter vector live in
`scripts/ci/check_poco_bft_v0_parameters.py` and `vectors/parameters-v0.json`.
Until equivalent vectors exist for every frozen object and another
implementation reproduces them, no implementation may claim complete wire
conformance. Comments, TOML formatting, and non-consensus status text are
excluded from the logical value.

## 12. Epoch, handoff, proof, and evidence digests

The exact logical fields for epoch commitments and handoff objects are
specified in `04-epochs-validator-sets-and-upgrades.md`. A handoff descriptor
is independently hashed as:

```text
Digest("trnm.poco-bft.handoff-descriptor.v0", HandoffDescriptorV0)
```

Handoff votes bind that digest. The enclosing vote and certificate use the
`handoff-vote` and `handoff-certificate` domains respectively; none of these
three domains is reused for another logical schema.

`CertifiedHeaderV0` has this exact nested CEV0 field order:

```text
header                        BlockHeaderV0
justify_qc                    QuorumCertificateV0
timeout_certificate           Optional<TimeoutCertificateV0>
epoch_anchor_authorization    Optional<EpochAnchorAuthorizationV0>
proposer_signature            Signature64
certifying_qc                 QuorumCertificateV0
```

The header supplies proposer ID, view, height, block ID, set, parameters,
chain, genesis, and version, so the verifier reconstructs the exact
`ProposalSignV0` and verifies `proposer_signature`. Block IDs and nested object
digests may appear redundantly in transport but are recomputed and are not
additional CEV0 fields.

`FinalityProofV0` has this exact CEV0 field order:

```text
schema_version                 u16
genesis_hash                   Hash32
chain_id                       ConsensusString
protocol_version               u32
epoch                          u64
validator_set_hash             Hash32
consensus_parameters_hash      Hash32
finalized_block                CertifiedHeaderV0
child                          CertifiedHeaderV0
grandchild                     CertifiedHeaderV0
```

Its digest is
`Digest("trnm.poco-bft.finality-proof.v0", FinalityProofV0)`. Every certifying
QC MUST authenticate its corresponding header. The child's exact
`justify_qc` digest MUST equal the finalized block's certifying-QC digest, and
the grandchild's exact justify digest MUST equal the child's certifying-QC
digest. If either proposal skips a view, its complete TC MUST be present,
verify at `proposal.view - 1`, and select that same exact QC digest. A proof
with only a peer-asserted justification digest and no proposer signature is
invalid. Ordinary finality proofs do not cross an epoch.

The mandatory `DoubleVoteEvidenceV0` logical value has this exact order:

```text
schema_version                 u16
first                          VoteEvidenceRecordV0
second                         VoteEvidenceRecordV0
```

Each `VoteEvidenceRecordV0` has the exact order:

```text
context                        CommonConsensusContext  // kind = vote
height                         u64
block_id                       Hash32
author_validator_id            Bytes
signature                      Signature64
```

Both contexts MUST be byte-identical, both authors MUST be the same active
validator, both signatures MUST verify, and the two `(height, block_id)`
tuples MUST differ. Records are strictly ordered by their reconstructed
`VoteSignV0` signing roots; arrival order is irrelevant. The evidence ID is:

```text
Digest("trnm.poco-bft.double-sign-evidence.v0", DoubleVoteEvidenceV0)
```

Proposal, timeout, and handoff equivocation may be transported as diagnostic
proofs, but they do not reuse this canonical preimage and have no active v0
economic disposition until a later freeze supplies their exact ID schemas.

Consumption Certificate fields and IDs are specified in `../poco-consumption-certificate-v0.md`.

## 13. Timestamp rule

For every non-genesis block:

```text
parent.timestamp_ms < block.timestamp_ms
block.timestamp_ms <= parent.timestamp_ms + max_block_time_step_ms
```

Both comparisons use checked unsigned arithmetic. The genesis timestamp is committed by genesis. Epoch seal blocks follow the same rule.

A node MAY reject or defer a proposal that is too far ahead of its local clock as an admission/DoS policy, but such a local-clock decision MUST NOT be used to produce a conflicting deterministic execution result. Correct validators need an interoperable operational clock-skew profile for liveness; it is not part of consensus validity in v0.

## 14. Size and decoding limits

At minimum, conforming decoders enforce the active committed limits for chain
ID, validator ID, logical block, and consensus-message bytes from
`parameters.toml`. These limits have exact, non-interchangeable meanings:

```text
logical_block_size_v0 =
    len(CEV0(BlockHeaderV0)) +
    4 + len(application_payload) +
    4 + sum(4 + len(evidence_i))
```

The last term uses the canonically ordered evidence list. Every addition and
length conversion is checked. A block is valid exactly when
`logical_block_size_v0 <= max_block_bytes`; equality is accepted. Proposal,
QC, TC, and transport sidecars are not counted. Compression, chunks,
redundant transport hashes, and stream framing cannot change this logical
size.

`max_consensus_message_bytes` is a decoded transport-body admission and
reassembly limit, measured after decompression and before external stream
framing. A declared or accumulated body above the limit MUST be rejected
before unbounded allocation. It is not a second consensus-validity size for a
nested block, QC, TC, proof, or other logical object: two transport envelopes
that decode to the same logical value cannot change that value's validity
merely because their transport overhead differs. P2 MUST freeze exact
chunking, compression-ratio, decompression-output, and framing limits before
network activation.

CEV0 object lengths are checked separately by their own `u16`/`u32` frames and
collection bounds; protobuf and CEV0 byte lengths MUST NOT be compared as
though they were the same encoding. Conformance vectors MUST cover exact
limit, limit plus one, evidence framing overhead, checked overflow, and two
different transport envelopes that decode to one equal logical block size.

Decoders MUST:

- reject lengths that overflow host indexing or allocation arithmetic;
- reject collections before allocating beyond their bounds;
- reject duplicate signer IDs, keys, QCs, evidence IDs, or certificate IDs where uniqueness is required;
- verify canonical order instead of sorting attacker-provided data and accepting it;
- reject trailing bytes and unknown enum discriminants;
- perform signature and expensive proof verification only after cheap structural and domain checks where safe.

## 15. Golden-vector requirement

P1 MUST add cross-language golden vectors for every domain, primitive boundary, object digest, valid signature, malformed encoding, threshold edge, and wrong-context replay. At least one independent implementation MUST reproduce the bytes and digests before the wire format is considered implemented.
