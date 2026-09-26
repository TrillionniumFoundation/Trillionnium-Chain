# M00 Protocol / Schema / Codec technical specification v1

Status: **module-specific implementation design; existing frozen inputs retained;
new local interfaces are planned; semantic acceptance and production activation not granted**.
Primary module: M00. Consumers: M01/M02/M03/M05/M06/M08/M13/M14.

## Authority

`docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` selects the applicable
profile. `bft-v0` imports all seven numbered specifications under
`docs/protocol/poco-bft-v0/`; `pcc1` imports those exact bytes and is not protocol
version 1. `ai-v1` requires its own separately accepted codec and parameter set.
A crate suffix, deployment setting or newer document does not select a decoder.

The existing source boundary is `trnm-consensus-types/src/cev0_decode.rs`, with
canonical writers in `canonical.rs`, object definitions in `block.rs`,
`certificate.rs`, `timeout_v0.rs`, `handoff.rs`, `handoff_sign_intent.rs`,
`epoch_activation_evidence.rs` and `parameters.rs`. Schema and vector authority
remains `docs/protocol/poco-bft-v0/schema/` and `vectors/`. This document does
not introduce another consensus encoding, signature domain or error number.

Target completion means every enabled external object has one bounded decoder,
one exact encoder, one contextual validator and an independently replayed vector
set. Structural path coverage alone is insufficient.

## Interfaces

### Frozen byte contract

| Item | Exact rule / authoritative definition |
|---|---|
| Unsigned scalars | Fixed-width big-endian u8/u16/u32/u64/u128; checked arithmetic. |
| Boolean | One byte, only 0 and 1. |
| Hash/key/signature | Exactly 32/32/64 bytes respectively. |
| `Bytes` | u32 byte length followed by that many bytes. |
| `ConsensusString` | u16 byte length, restricted ASCII `[a-z0-9][a-z0-9._:-]{0,127}`. |
| Optional/list/enum | u8 tag 0/1; u32 count; one schema-defined u8 discriminant. |
| Struct | Concatenated fields in frozen schema order, without field tags. |
| Digest | SHA-256 of `Frame("trnm.cev0.hash.v0") || Frame(domain) || Frame(CEV0(value))`; Frame is u32 byte length plus bytes. |

The complete field orders are in specification 03 and its logical schemas;
copying a subset here does not create a competing layout. Wire protobuf framing
is a carrier. Neither protobuf bytes, JSON nor hexadecimal text is a signing
preimage. Unknown fields, implicit defaults, duplicate set entries, floats,
varints and trailing bytes are rejected, not normalized.

The frozen Core-to-signer envelope is `CanonicalSignIntentV0`: schema u16,
chain string, protocol u32, epoch u64, set hash32, author Bytes, positive
first-authorizing Safety revision u64, preimage variant u8, exact Vote or
Timeout preimage, signing root32, then fingerprint32. Its fingerprint uses the
existing `trnm.poco-bft.sign-intent.v0` domain. A later unrelated Safety revision
must not rewrite the same intent. Handoff uses its separate existing intent
codec and role; it must never be cast into Vote/Timeout.

### Admission API and ownership

Existing `Cev0AdmissionBudgetV0::for_validator_set(parameters, validator_set)`
derives limits from the supplied profile and set cardinality; that helper does
not authenticate them. The enclosing admitted-context boundary must first prove
that the parameter hash matches the committed set. A constructed budget alone
is not a trusted-context capability.
`decode_consensus_parameters_v0_exact` is the exact parameter entry point;
other public object decoders must retain their declared contextual parameters.
`DecodeError` carries `code()` and `byte_offset()`; M14 may expose a stable
projection but may not discard that distinction internally.

Planned adapter signature, local Rust API only:

```text
decode_admitted<T>(
  profile: AuthenticatedCodecProfile,
  kind: EnabledObjectKind,
  bytes: &[u8],
  budget: &mut Cev0AdmissionBudgetV0
) -> Result<DecodedInert<T>, AdmissionFailure>
```

`AuthenticatedCodecProfile` has immutable chain/genesis/protocol, active set and
parameter commitments, object allowlist, and authenticated preimages.
`DecodedInert<T>` exposes data, never signing/commit/activation authority.
No generic `Deserialize` path constructs M01 verified tokens. M01 consumes the
inert object and independently supplied expected target to perform verification.

### Epoch finality and ordered membership consumers

The explicit `decode_epoch_first_finality_proof_v1_exact_with_budget` consumer
accepts only a separately decoded complete eight-preimage activation context.
It reconstructs the expected authorization bytes, admits exactly that synthetic
new-epoch anchor, and checks C+3's kind/parent/activation coordinates before
canonical re-encoding and exact EOF. The ordinary and genesis consumers still
reject epoch anchors. Decoding yields inert proof data; M01 performs the strict
signature and independently trusted context verification.

Every certified header charges its proposer signature as well as QC/TC work.
Nested failed attempts retain their charged budget. The shared
`OrderedInclusionProofV0` generator/verifier uses the existing ordered-root
domains and checks count/index, exact path length and canonical odd-leaf padding;
it introduces no new consensus hash or root algorithm. M05 separately authenticates
the root through strict finality before interpreting membership as evidence.

### Other owned foundation packages

These packages have different encodings and authority boundaries. The table
specifies their retained contracts; shared admission rules below apply only
after the caller selects the correct package/schema. A shared `Hash32` width
does not authorize conversion between their IDs or signing domains.

| Owned package / source API | Current behavior and consumer contract | Rejection, state and required acceptance cases |
| --- | --- | --- |
| `trnm-types`: `ObjectRef`, `TaskObject`, `TaskMetadata::compatibility_report`, `TransferTx::{signing_message,validate_basic}`, `IdentityRegistry`, `RelayAuthVerifier` | Compatibility DTOs and in-memory identity/relay helpers consumed by legacy state/RPC and tooling. `ObjectRef` binds numeric id/version; metadata compatibility findings remain visible to the consumer. Transfer signing and relay envelopes retain their own source formats; neither is CEV0 nor the M05 intent format. `IdentityRegistry::{register_did,issue_capability,revoke_capability,renew_capability,revoke_did,verify_capability}` uses explicit subject/scope/height checks. | Preserve `TransferTxValidationError`, `InteropIdentityError` and `RelayAuthError::stable_code`; reject expired/revoked/wrong-scope capability and stale relay nonce under the selected verifier mode. In-memory maps and audit trail are not durable identity authority. Test metadata fallback versus missing required fields, transfer signature/address mismatch, strict versus compatibility relay handling, and revoke/renew boundaries at exact heights. |
| `trnm-protocol`: `CanonicalTxV1::validate`, `CanonicalCommandV1::validate`, `AccountV1`, `TaskV1`, `FeePolicyV1`, `MonetaryStateV1` | Existing native JSON transaction/object schema used by M06 `trnm-runtime`. Transaction fields are exact schema, sender, positive nonce/max_gas/fee_limit and typed command; u128 uses the crate's canonical decimal serde codec. `account_key`, `task_key`, `fee_policy_key` and `monetary_state_key` own key derivation. Validation establishes shape, not account authorization, balance, current nonce or finality. | Preserve `ProtocolError::{UnsupportedSchema,NonCanonical,NonPositive,InvalidDeadline,OutOfRange}`. Source limits include ID 160 bytes, lowercase hash text 64 bytes, challenge window at most 1,000,000 blocks and bounded gas parameters. No persistence is owned here. Test unknown fields/schema, decimal spelling/overflow, invalid deadlines, key-domain separation and result commitment vectors. M06 must reject or meter before execution; no automatic JSON-to-CEV0 reinterpretation. |
| `trnm-poco-order-types-v1`: `Cev1EncodeV1`, `decode_block_header_v1`, `decode_quorum_certificate_v1`, `derive_block_id_v1`, `derive_vote_signature_root_v1`, `G2ManifestBoundInputV2` | Exact CEV1 Order header/vote/QC data and typed `BlockIdV1` are candidate AI-native contracts consumed by M08 Order preview and M13 verifier. `*_prefix_v1` is usable only within a caller-bounded enclosing codec; external admission uses exact decoders. `derive_g2_ordered_list_roots_v2` commits manifest-ordered items before sealing the containing header; G2 input has no candidate block-id field. | `OrderTypeCodecErrorCodeV1` rejects truncation/trailing bytes and malformed canonical fields. Existing limits: consensus string 1,024 bytes, validator ID/signature 128 bytes each, certificate signers 256. No signature verification or durable authority follows from decode. Preserve compile-fail tests separating v0/v1 IDs and forbidding self-candidate binding; add exact/prefix suffix tests, ordered-root permutations and domain-separated golden vectors. |

Planned adapters must name the input schema and output schema in their signed
deployment profile and perform an explicit validated translation. Until such
an adapter exists, unsupported legacy/candidate formats return a typed
unsupported-format result at M05/M06/M14 ingress. Do not add their mutable
compatibility maps to the consensus production closure merely to reuse DTOs.

### Owned auxiliary packages: audit events and protobuf transport

`contracts/audit-events/src/lib.rs` is a non-authoritative event value library.
`AuditEvent::new(source,event_type)` sets all optional fields absent; builders
set actor/object_id/related_id/reason/note strings and optional u128 amount.
Its current struct has no signature, persistence or canonical wire encoder and
its setters are infallible; an event is never reconstructed as a commit receipt.
The owning contract must append an event only after its actual state transition,
with actor derived from authenticated execution rather than an arbitrary field.

Planned bounded export `encode_audit_event_v1` uses local schema u16=1, u16-length
UTF-8 source/event_type, then option tags 0/1 for actor/object/related strings,
amount u128-be, reason and note, in that order; present strings use u32 byte length.
No normalization or implicit empty/present conversion occurs. It returns local
`UnknownEventKind`, `FieldTooLong` or `RecordTooLarge` before publication, not a
consensus error. An opt-in test profile caps source/type at 128 bytes, actor/object/
related/reason at 256, note at 2048 and record at 4096; deployment chooses signed
limits. `new_preserves_source_and_event_type`, absent-field and builder tests are
existing; add exact encoding/absence/maximum+1/overflow export vectors. This
new export does not retrospectively become contract signing bytes.

`proto/trnm/poco/bft/v0/` is the owned transport projection. `WireEnvelope` fields
1..16 carry schema/wire version, genesis/chain/protocol/epoch/view, set/parameter
hashes, optional consensus-kind marker, body_kind, sender/message/sequence and
optional semantic hash; body tags32..45 form oneof. Validate the body_kind/oneof
match and duplicated context against the admitted CEV0 object before M04 hands
it to Core. Sender_node_id is transport attribution, not validator authority.
Honor reserved tags (including envelope64..127 and kind32..63); unsupported tags
or duplicate body claims fail under the exact accepted envelope decoder rather
than silently selecting another body. Bounded decompressed body admission uses
active parameters, while sender/message-ID maxima come from M04's profile.

The other projections cover consensus, epoch, evidence, light client and
`proto/trnm/poco/v0/consumption_certificate.proto`. Generated protobuf bytes and
body_semantic_hash never enter a consensus signing preimage. Proto compiler
version/checksum and generated descriptor identity are build inputs; regeneration
must preserve tags and independent decoded-object→CEV0 vectors. The AI-v1 proto
folder is presently a placeholder pending its logical schema freeze, not a
negotiable v0 upgrade. Test oneof/context mismatch, unknown versions, reserved
fields, missing body, oversize expansion and every body-kind round trip.

## State machine

M00 is pure and has no durable state. One operation advances through
`ContextChecked -> RootBounded -> StructurallyDecoded -> SemanticallyChecked -> ExactEOF`.
A failure terminates the operation; no partially decoded list escapes.

1. Resolve profile and object kind from authenticated configuration, not bytes
   supplied by the same peer. Reject unsupported combinations without fallback.
2. Admit outer byte length before allocating or decompressing nested objects;
   transport expansion is independently bounded by M04.
3. Read fixed discriminants and lengths with checked offset addition. Compare
   every count/byte length to both object and remaining-input bounds before
   allocation, iteration or copy.
4. Parse fields once. For sets, enforce the schema's exact sort key and strict
   uniqueness. Do not sort a noncanonical wire object into acceptance.
5. Validate relations: header context, set/parameter identity, signature share
   identity, QC/TC references, epoch geometry and exact optional-field rules.
6. Reserve declared nested signature work before M01 attempts verification.
   A budget belongs to the whole admission operation; restarting a decoder
   cannot reset previously spent cryptographic work.
7. Require exact EOF. For persisted signer objects additionally re-encode and
   require byte equality before journal lookup or custody.
8. Return only the complete inert object and consumed-byte count equal to input
   length. Unknown version never selects a nearest known version.

Protocol truncation/noncanonical/order/unknown-tag failures use existing
`DecodeErrorCode`, including `TrailingBytes`, `InvalidSchemaVersion`,
`InvalidProtocolVersion`, `InvalidOptionalTag` and the relevant object error.
An unsupported deployment profile is planned local `UnsupportedProfile`.
An absent authenticated context is `Unavailable(ContextMissing)`.
Operational work exhaustion is `Unavailable(AdmissionBudgetExhausted)` at the
adapter; a protocol maximum violation remains deterministic rejection.
Neither local outcome becomes equivocation evidence. Offset meanings remain
those frozen by the exact decoder; do not fabricate an offset for remote I/O.

## Persistence and recovery

M00 writes no database or journal. M03/M07 store original canonical bytes with
an explicit local schema identifier; local wrappers cannot alter their payload.
After restart, decode the exact stored bytes under the stored authenticated
context and repeat validation before constructing any capability.

A storage schema upgrade must distinguish outer local format migration from
consensus preimage changes. Persist old and new format identities in the
migration record; compare the decoded consensus object's canonical bytes
before and after. Unknown schema or noncanonical old record fences that
record's consumer. No automatic repair, rehash or default insertion is allowed.

The eight-preimage epoch recovery carrier is not a frozen aggregate
`EpochHandoffProof` encoding. Keep each component exact and separately bounded;
do not invent an aggregate wire hash/domain to make it transportable.
Planned local epoch records in M02/M07/M08 remain local versioned metadata.

## Resource bounds

Read limits from the authenticated `ConsensusParametersV0` and selected object
schema; source hard ceilings further restrict allocations. Current reference
values are 4 MiB block bytes, 8 MiB consensus message/root bytes, 100 validators,
128-byte chain/validator identifier bounds and three certified blocks for
finality. These are reference-profile values, not unconditional production defaults.

`MAX_CEV0_CERTIFICATE_ITEMS=100` and
`MAX_CEV0_TC_AGGREGATE_SIGNATURE_SHARES=100*100` bound nested TC shares.
The complete signature-work budget also includes outer Timeout/Proposal and
other proof signatures; 10,000 is not a blanket all-object verification budget.
Use source `MAX_CEV0_*` constants and schema bounds for handoff/sign-intent sizes.

A deployment profile may reduce local queue/work limits without changing
consensus validity: it returns unavailable and permits retrieval/retry.
It may not silently reduce a consensus maximum and label an otherwise valid
block invalid. Planned profile loading validates positive values, checked
products and enough capacity for one maximum enabled object. Missing limits
block enabling that object; no guessed production fallback is installed.

## Security

Differentiate structural canonicality from cryptographic authenticity and from
application authority. A correct checksum proves neither trusted origin nor
freshness. The caller may not select a trusted validator set by presenting its
own matching hash. Node-local signer errors remain outside peer B2-A..E taxonomy.

Any schema/compiler generator must produce deterministic output and fail when
checked-in output differs. It must not generate a new domain from type names.
Only M00's reviewed registry assigns codec versions/error meanings; additions
that alter frozen bytes require an explicit protocol change, not a parser flag.

## Observability and SLO

Measure bytes, objects, nested shares, charged signature work and rejection class
per profile/kind. Export bounded counters; never log private keys, raw secrets
or unlimited rejected payloads. Record first failing offset and a bounded digest
for diagnostics. Report decode time and peak retained bytes separately from
M01 verification time; numeric SLOs belong to the qualified deployment profile.

## Verification and evidence

Existing corpora include `wire-foundation-v0.json`, `wire-envelope-v0.json`,
`wire-authenticated-v0.json`, `wire-semantic-v0.json`, `parameters-v0.json`,
`qc-tc-threshold-v0.json`, checkpoint/handoff and signer-intent foundation cases.
`consensus_parameters_decoder_round_trips_and_exhausts_the_exact_root` is an
existing source regression, not coverage of every enabled object.

Required acceptance cases, each with exact input bytes and code/offset:

- `M00-CANON`: independent encoder matches bytes and digest for every enabled kind.
- `M00-PREFIX`: all truncated prefixes, one trailing byte and unknown tags reject.
- `M00-BOUND`: each scalar/list/aggregate maximum and maximum+1; overflow before allocation.
- `M00-DOMAIN`: same payload under each wrong chain/genesis/domain/profile fails authentication.
- `M00-REGISTRY`: every reachable decoder result maps to one registered scope/code.
- `M00-NESTED`: TC share/accounting maxima, duplicate QC reference and failed-work retention.
- `M00-MIGRATE`: local format migration preserves exact protocol bytes and rejects unknown versions.

M00 supplies bytes/errors; M01 verifies them independently; M02/M03/M13 replay
those same cases at their actual ingress. Fuzz prefix/length arithmetic and
nested allocation, with retained-byte/work assertions, not only no-panic checks.

## Historical header context (M00-HISTORY-V1)

`validate_historical_header_link_v1(header, parent, active_set, parameters)` is
an inert structural helper for M01-HISTORY-V1. It reuses the existing exact
header/set/parameter, leader and timestamp checks and `EpochGeometryV0` without
allocating a new wire tag or hash domain. Parent ID and height must be exact;
same-epoch views increase, while an epoch-change handoff starts a fresh positive
view after the scheduled old seal2. It checks the unchanged chain identity and
seal carried roots/commitment with empty payload/receipt/evidence roots. It does
not claim QC, TC or proposal-signature verification and cannot authorize Core,
signing or application execution. Strict terminal finality and original ordered
activation evidence separately authenticate the complete linked history.

## Contextual successor activation (M00-SUCCESSOR-EVIDENCE-V1)

For M01-SUCCESSOR-PRE-HANDOFF-V1, the narrow
`FinalityProofV0::validate_checkpoint_two_seal_structure_v1(old_set,
old_parameters, commitment) -> Result<()>` reuses only the existing specialized
checkpoint/two-seal geometry, empty seal roots, carried state and commitment
relations. It does not validate generic finality, authenticated ancestry or any
signature, and returns no kernel or authority token. The strict consumer must
first decode under the complete authenticated runtime context and separately
perform strict runtime finality verification. Existing verifier-based kernel
APIs keep their original verification semantics and frozen bytes unchanged.

This candidate interface is implemented by `epoch_activation_evidence.rs` and
`joint_handoff.rs`, with strict consumer verification in M01. Frozen v0 bytes
and context-free decoder behavior remain unchanged. A checkpoint proof in an already
activated epoch may contain a timeout certificate with a reference to that
epoch's authorized synthetic anchor. The reference names the predecessor's
terminal seal and view0; it does not name the first application block.

`decode_epoch_activation_evidence_with_context_v1_exact(preimages,
predecessor_context, budget)` uses the complete inert
`EpochRuntimeContextDataV1` as decoding context. Its active set and parameters
are the predecessor context's new set and parameters. Decode the same eight
canonical roots and reuse the existing aggregate byte/work limits, parent
binding, commitment/configuration checks and complete composition relations.
Decode the checkpoint proof through the existing bounded runtime finality parser,
then require the exact checkpoint/two-seal geometry, commitment and
state-preserving empty seals. Exact reencoding and parser exhaustion are mandatory.
Structural failure keeps the supplied meter unchanged; successful decoding reserves
all later signature work. The old v0 entrypoint supplies no predecessor context
and continues to reject unauthorized synthetic references.

Factor checkpoint relations and joint composition into shared internal functions.
`derive_successor_epoch_joint_structure_v1(decoded, predecessor_context)` returns
only the existing inert joint facts after complete structural checks, including
exact active set/parameters and exact synthetic-reference binding. It performs no
signature verification and cannot create M01 strict authority. Its public contract
must say so explicitly. Existing verifier-based v0 wrappers continue performing
all their original signature checks before returning the same inert facts.

M01 consumes these structural results only together with an independently verified
predecessor and strict checkpoint, terminal-QC and both-role handoff verification.
No bare set, kernel, peer-provided anchor or stored digest can replace that owner.
The new decoder and structural path require real signed skipped-view checkpoint
fixtures, changed-context/anchor negatives, all retained two-seal mutants,
canonical-byte rejection and exact work-boundary tests.

## Activation boundary

The design authorizes implementation work, not new network formats. A new
object remains disabled until its field layout, bounds, error mapping and
independent expected vectors are registered and consumed. Existing frozen
objects continue using their current codecs while planned adapters are built.
All source references and vector outcomes must bind the implementation commit;
this document claims neither executed tests nor production promotion.
