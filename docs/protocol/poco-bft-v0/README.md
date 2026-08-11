# PoCO-BFT v0 Protocol Freeze

Status: **P0 normative design freeze; implementation target, not an implementation or readiness claim**

The host/Core production integration contracts are frozen separately in
[`../../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`](../../architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md).
They define the required durable SafetyState codec, complete SignIntent,
validation job/outbox, ordered finalization queue, speculative overlay and the
consensus-parameter/local-backpressure boundary. None is an activation claim.

Freeze date: 2026-08-04

Last pre-activation normative correction: 2026-08-05

Protocol version: `0`

## 1. Scope and normative language

This directory freezes the consensus-critical behavior targeted by PoCO-BFT v0. The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as normative requirements.

The freeze covers:

- the system and threat model;
- a deterministic chained-QC consensus state machine;
- canonical signed and hashed preimages, domain separation, and wire limits;
- validator-set snapshots, epoch handoff, and protocol-version activation;
- deterministic integer PoCO/bond-derived validator weights and rollout gates;
- light-client verification and weak-subjectivity recovery;
- safety/liveness invariants and the P0 exit criteria.

This freeze does **not** claim that the protocol is implemented, formally proved, audited, production-ready, or economically secure. A conforming implementation still requires the P1–P4 work described in the architecture freeze.

Items explicitly marked `UNDECIDED` are outside the frozen v0 safety kernel or must fail closed. An `UNDECIDED` item MUST be resolved before any deployment phase that depends on it. Implementations MUST NOT silently choose consensus-affecting behavior for such an item.

## 2. Normative documents

The documents are read together. If two passages appear to conflict, the more specific rule wins; an unresolved consensus-affecting conflict blocks implementation and MUST be repaired in this freeze.

1. [System model and threat model](01-system-model-and-threat-model.md)
2. [Chained-QC consensus](02-chained-qc-consensus.md)
3. [Wire, cryptography, and domain separation](03-wire-crypto-and-domain-separation.md)
4. [Epochs, validator sets, and upgrades](04-epochs-validator-sets-and-upgrades.md)
5. [PoCO weights, bond, and accountability](05-poco-weights-bond-and-slashing.md)
6. [Light client](06-light-client.md)
7. [Invariants and conformance](07-invariants-and-conformance.md)
8. [`parameters.toml`](parameters.toml), the machine-readable reference parameter profile

The current independent golden-vector subset is indexed in
[`vectors/README.md`](vectors/README.md).

The current Rust prototype's release-blocking differences from this freeze are
tracked in [`IMPLEMENTATION_GAP_REGISTER.md`](IMPLEMENTATION_GAP_REGISTER.md).

The logical Consumption Certificate is frozen separately in
[`../poco-consumption-certificate-v0.md`](../poco-consumption-certificate-v0.md).

The architecture and delivery boundary is frozen in
[`../../architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`](../../architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md).

## 3. Protocol summary

PoCO-BFT v0 is a partially synchronous, authenticated, chained HotStuff-family state-machine-replication protocol. Validators vote with a fixed, epoch-scoped effective weight. A quorum certificate (QC) requires

```text
quorum(W) = floor(2 * W / 3) + 1
```

where `W` is the total effective voting weight of the exact active validator-set commitment for the epoch.

A direct chain of three certified blocks finalizes the oldest block. More precisely, for blocks `b0 <- b1 <- b2`, all three blocks MUST have valid QCs, the parent relationships MUST be exact, heights MUST increase by one, and views MUST strictly increase. Learning `QC(b2)` finalizes `b0` and its ancestors.

The protocol's safety mechanism is the validator lock plus persist-before-sign. A validator MUST durably record its consensus decision and monotonic safety state before releasing a vote, timeout, or epoch-handoff signature. A timeout certificate changes view; it never finalizes a block and never unlocks a validator by itself.

PoCO does not make consumption itself a finality signal. Finality comes only from BFT quorum signatures. At an epoch snapshot, matured and capped Consumption Certificates determine a candidate raw capacity; active slashable bond independently caps that capacity. The committed validator set is immutable during the epoch.

The closed B2-G calculation kernel operates on a caller-supplied normalized
snapshot transcript. It proves deterministic arithmetic, candidate/fallback
selection, and exact validator-key PoP verification for those supplied facts;
it does not prove that a full Consumption Certificate, bond, registration, or
eligibility fact came from finalized application state. A successful `shadow`
calculation carries old membership and weights with reason `0`; that protocol
rule is not fallback.

## 4. Frozen choices

The following choices are frozen for v0:

- full validator sets; no sampled committees;
- Ed25519 individual signatures and SHA-256 digests;
- transport-independent canonical encoding `CEV0` for every signed or hashed preimage;
- one normal vote per `(genesis_hash, chain_id, protocol_version, epoch, view)`;
- an unweighted round-robin leader over the canonical validator order;
- weighted quorum with `floor(2W/3)+1` and unique signers;
- three-certified-block finality;
- timeout certificates that carry signed `highQC` digests but cannot unlock/finalize;
- fixed-length reference epochs and joint old-set/new-set handoff certificates;
- deterministic checked-`u128`, floor-only PoCO/bond arithmetic;
- rollout sequence `shadow -> eligibility-only -> capped-weight -> full`, with governance-controlled epoch-boundary promotion;
- trusted-checkpoint light clients with a finite weak-subjectivity period.

Review clarification on the freeze date: QC ordering and TC high-QC selection
use `(view, block_id, qc_digest)`, not only `(view, block_id)`. Two valid QCs
for the same block may have different canonical signer subsets and therefore
different digests; the third key makes selection unique without treating that
benign case as conflicting finality. Same-view QCs for different block IDs
remain a mandatory safety halt.

The 2026-08-05 pre-activation correction closes three review-discovered
ambiguities without preserving experimental compatibility: `GenesisQC` and
`EpochAnchorQC` now have exact empty-signature QC preimages and
context-authorized validity; `FinalityProofV0` carries complete signed header
proposals, exact justifications, and skipped-view TCs; and the first block of
an epoch may move beyond view 1 through a TC selecting its authorized anchor.
It also adds the previously missing
`trnm.poco-bft.handoff-descriptor.v0` domain. All earlier experimental
CommitProof/finality and handoff digests are invalid and MUST NOT be upgraded
by inference. No production or public interoperability promise existed for
those values.

## 5. Explicitly deferred or undecided

The bounded protobuf body projection under `proto/trnm/poco/bft/v0` is frozen
as the v0 reference network container. Protobuf bytes remain transport only;
they are never CEV0 signing or hashing preimages. The following operational
transport layers and other choices remain outside the v0 safety freeze:

- authenticated session establishment, external stream framing, compression,
  RPC method layout, peer discovery, and RPC/P2P multiplexing (`P2`);
- aggregate or threshold signature schemes (`DEFERRED`);
- weighted leader selection (`DEFERRED`);
- validator committee sampling (`DEFERRED`);
- mainnet economic constants and slash fractions (`UNDECIDED`);
- privacy-preserving consumption proofs and related-party detection policy (`UNDECIDED`);
- the concrete governance transaction schema and upgrade payload format (`UNDECIDED`).

Changing a frozen choice requires a new protocol version and the epoch-boundary upgrade procedure. Tuning a parameter without changing semantics requires a finalized parameter-set commitment and is still subject to the same activation rules.

## 6. Safety and liveness statement

Safety is conditional. It requires collision resistance of SHA-256, unforgeability of Ed25519, deterministic correct execution, non-rollback durable signing state, and strictly less than one third Byzantine effective voting weight in every active epoch. During a validator-set transition, the bound applies separately to both the old and new sets.

Liveness is also conditional. It is expected only after the network reaches a Global Stabilization Time, messages between correct online validators are eventually delivered within a bounded delay, enough correct effective voting weight is online, and the pacemaker eventually selects a correct leader with a sufficient timeout. The protocol makes no unconditional asynchronous-liveness claim.

## 7. Conformance posture

Before a P1 prototype may be designated a conforming candidate, every
safety-relevant field, comparison, transition, threshold, and signing preimage
MUST be unambiguous. An implementation is conforming only if it passes the
golden-vector, state-machine, fault-simulation, formal-model, recovery, and
interoperability obligations in `07-invariants-and-conformance.md`.

Current local development gates are:

```sh
./scripts/ci/check_poco_bft_v0_parameters.py
./scripts/ci/check_poco_bft_v0_wire_vectors.py
./scripts/ci/check_poco_bft_v0_anchor_finality_vectors.py
./scripts/ci/check_poco_bft_v0_ordered_roots.py
./scripts/ci/check_poco_bft_v0_qc_tc_vectors.sh
./scripts/ci/check_poco_bft_v0_logical_schema.sh
./scripts/ci/check_poco_bft_v0_anchor_handoff_schema.sh
./scripts/ci/check_poco_bft_v0_handoff_vectors.sh
./scripts/ci/check_poco_bft_v0_epoch_commitment_schema.sh
./scripts/ci/check_poco_bft_v0_block_body_schema.sh
./scripts/ci/check_poco_bft_v0_checkpoint_finality_schema.sh
./scripts/ci/check_poco_bft_v0_joint_handoff_schema.sh
./scripts/ci/check_poco_bft_v0_snapshot_candidate_schema.sh
./scripts/ci/check_poco_bft_v0_consumption_certificate_schema.sh
./scripts/ci/check_poco_bft_v0_snapshot_namespace_schema.sh
./scripts/ci/check_poco_bft_v0_snapshot_transition_schema.sh
./scripts/ci/check_poco_bft_v0_checkpoint_execution_schema.sh
./scripts/ci/check_poco_bft_v0_business_semantics_schema.sh
bash scripts/ci/check_poco_bft_v0_application_authority_schema.sh
bash scripts/ci/check_poco_bft_v0_application_operation_sequences.sh
bash scripts/ci/check_poco_bft_v0_authenticated_candidate_selection.sh
bash scripts/ci/check_poco_bft_v0_authenticated_next_epoch_commitment.sh
bash scripts/ci/check_poco_bft_v0_authenticated_checkpoint_handoff.sh
./scripts/ci/check_poco_bft_v0_formal.sh
PROTOC=/path/to/protoc-29.3 ./scripts/ci/check_poco_bft_v0_proto.sh
```

The parameter, foundational-wire, ordered-root, B1 QC/TC, and partial
anchor/finality gates independently reconstruct their committed CEV0 bytes and
digests. The anchor/finality gate is explicitly shape/relationship evidence
and does not validate complete handoff authorization, composite signatures, or
weighted quorums. The B2-A logical-schema gate independently exact-decodes the
ordinary certificate-kernel raw bytes, rejects the bounded mutation corpus,
and detects declared protobuf-projection drift; it does not decode a network
envelope or cover the objects excluded by its manifest. The B2-B structural
gate extends exact decode and projection checks only through the listed
anchor/handoff certificate-kernel objects; its shape fixture deliberately
claims no cryptographic validity. The separate B2-B handoff-vector gate uses
two distinct weighted validator sets and real Ed25519 signatures to verify the
terminal ordinary QC and both old/new handoff roles, while binding exactly one
inert epoch-anchor candidate encoding. It does not authorize or emit an
`EpochAnchorQC` or prove checkpoint/two-seal ancestry. The B2-C gate closes the
exact inert `NextEpochCommitmentV0` object and its same-version v0 context
relations: three raw objects, 608 incomplete prefixes, three trailing cases,
25 parser boundaries, and 21 context mutations. It emits no transition or
anchor capability and does not authenticate snapshot/runtime/set preimages,
governance, upgrades, or a complete epoch transition. B2-D, B2-E, and B2-F
respectively close the ordinary body, narrow checkpoint/two-seal, and same-
version fields-1-through-11 composition kernels under their documented inert
boundaries. B2-G adds a deterministic candidate/fallback and PoP gate over
`UnauthenticatedCandidateSelectionTranscriptV0`: the independent lane must
reproduce the normalized input relations, checked arithmetic, cap hierarchy, deterministic
selection/tie-breaks, rollout weights, shadow reason-0 carry, lowest fallback
reason, exact fallback set, and strict Ed25519 PoP negatives. Its Rust success
type is private-field `CandidateSelectionKernelV0`; neither lane authenticates
the transcript's state provenance or mints an anchor/transition capability.
The epoch-zero core also
fails closed at the mandatory checkpoint height across ingress, signing, and
recovery; this fence is not checkpoint/seal/handoff support. The formal gate combines bounded seeded exploration
with required failing mutants. The proto gate compiles a descriptor for
transport schemas; it does not make protobuf the
signed encoding or replace strict semantic validation. Passing these partial
gates does not satisfy the complete P0 exit criteria above.

The exact finalized cutoff-header relation and complete Consumption
Certificate logical wire/cryptographic-admission kernel are closed as B2-H1.
The cutoff-rooted JMT/ICS23 snapshot namespace, manifest-relative
completeness, membership and explicit non-membership kernel is now closed as
B2-H2. B2-H3a now freezes the fifteen exact semantic-value layouts and an
atomic compare-and-set entry/manifest JMT transition kernel. Empty ordinary
versions carry the previous manifest; a scheduled cutoff explicitly refreshes
its height even when empty. B2-H3b1 now seals that exact physical projection
across in-memory codecs, SQLite startup/migration and precommit, and ABCI
snapshot restore v3/v4, rejecting hidden or malformed namespace leaves before
any SQLite row is written. It still authorizes no production PoCO mutation
source. B2-H3b2a now genesis-authenticates the chain/genesis/profile authority
and binds the actual proposal/finalization block, contiguous parent AppHash,
one sealed historical cutoff version/root/projection and manifest root/count,
ordered payload, exact execution-result bytes,
and post-execution AppHash into a private checkpoint capability whose canonical
size is `404 + chain_id.length` bytes (405..532); the fixed 21-byte-chain-ID
corpus is 425 bytes. Transaction bytes and encoded receipt bytes each have an
8 MiB aggregate ceiling, and count/size checks precede encoding and hashing.
The emitted `trnm.poco.checkpoint-execution.v0` event and execution ID are
telemetry only and cannot reconstruct or authorize that private capability.
A four-entry `(JMT version, state_root)` projection cache is performance-only:
real roots are rechecked on hit and after load, and hit/miss/eviction cannot
change admission or capability bytes.
B2-H3b2b0 now closes only the pure semantic transition layer: the H3a exact
decoder supplies the typed fact used by CAS validation; enum and block/epoch
clock meanings, the monotonic `max_accepted_nonce` watermark, immutable
consumer-key/meter cores with one-way revoke/retire, the settlement/
registration/lifecycle/rollout graphs, create-only records, and the all-kind
delete ban are frozen. B2-H3b2b1 now appends exact kind-16 application
authority without changing kinds 1--15. Its exact validator, production strict
Ed25519 certificate/PoP paths, pre-clone capacity checks and common overlay seal
are implemented and gated. The private next-height context binds the committed
parent AppHash, chain/genesis, active epoch/parameters and AppHash-authenticated
governance signer commitment. Status strings, normalized truth cases and other
side facts are diagnostics only and cannot replace raw state, operation bytes,
proofs or authenticated context.

The canonical nine-sequence H3b2b1 artifact closes its five production
full-store automata and four isolated prune-transition automata: 18 successful
production/JMT steps, nine authoritative no-write/head-unchanged negatives,
independent Node `check-final`, and a non-ignored Rust production replay
consumer. The 210-case truth table and focused kernel tests remain lower-layer
evidence rather than substitute authority.

The four certificate, consumer-key, meter and validator prune paths remain
isolated prune-transition/real-JMT test kernels. Their retention
boundaries cross epochs, while the production context remains restricted to
the active epoch. Production prune reachability requires Core activation plus
an authenticated next-epoch configuration transition and is not an H3b2b1
closure claim.

H3b2b2's implementation now performs that one-call application-authenticated
join. The same private historical cutoff projection authorizes checkpoint
execution and then supplies the complete internally reconstructed transcript to
hard-coded strict Ed25519/PoP admission and a fresh B2-G calculation. Kind 16
retains separate future-candidate registrations for new/changed successor-epoch
keys; old-set membership alone is not registration authority. The mapping uses
finalized approved parameters or exact active-parameter no-change carry,
historical acceptance epochs, independent-only relationships, exact challenge
eligibility, full target-plus-evidence bond coverage, and equality-expiring
jail state. Caller transcripts, generic verifiers, events/status and the old
inert B2-G token have no input path.

This remains short of H3b2b2 closure, but the bounded shared raw schema/vector
has landed. Independent Node reconstruction from continuous physical history
and raw cutoff/head projection reproduces strict PoP, fresh B2-G and every
authorization seal; a non-ignored Rust test freshly rebuilds the same JMT
fixture/one-call result and requires exact corpus equality. The positive has
four mature reason-0 candidates and the complete authenticated fallback freezes
reason 3.

Both canonical scenarios now additionally run through a non-ignored production
application evidence test. Independent instances start from the exact
production-valid epoch-0 empty authority, use the explicitly test-only height-24
source bootstrap, then execute the normal height-25 cutoff refresh, height-27
parent and height-28 checkpoint. The production execution used by
`ProcessProposal` and the independent `FinalizeBlock` execution derive equal
private capabilities. V3 parent restore, periodic SQLite V4 cutoff-25 restore
followed by parent 27, SQLite restart, cache miss/hit and fresh post-checkpoint
reconstruction from retained cutoff 25 reproduce the same result. Zero block
hash rejection leaves head, pending state and cutoff projection unchanged,
including across restart. The height-24 bootstrap is not a production
application operation, rollover or Core transition. A targeted SQLite pruning
test also advances the retained query floor to 26, physically removes cutoff
25, and proves reject/fail-stop plus restart-stable unchanged head, pending and
source.

Node now recomputes historical JMT roots, enforces complete physical namespace
membership, exact-decodes every kind payload, and executes the root-consistent
mutation families frozen in the shared schema. The only bounded hardening items
left are a cache/restart TOCTOU mutation beyond deterministic replay and an
AST/type-aware API-surface gate. Production epoch activation must also normalize
kind-16 usage buckets: current-span meter
buckets may be retained, expired buckets are removed, and consumer/provider,
task/provider and provider buckets from an older epoch are removed rather than
relabeled. The helper/kernel boundary exists, but Core cannot yet drive this
atomic rollover, so it remains an H3b2b2a production gap.

H3b2b3a now adds bounded, domain-separated post-execution and cutoff-only
crate-private joins over the unified
lead-3 witness: regular parent 24, finalized cutoff 25, regular child 26,
regular grandchild 27, and the authenticated candidate produced by height-28
checkpoint execution. The bridge exact-decodes raw `FinalityProofV0` CEV0
against the authenticated old context and parent timestamp, then freshly
verifies it with strict crypto; the parent header is also exact-decoded and H2
is rerun from its raw proof bundle. Its private seal binds the verified H2
absence count and therefore hard-requires that count to be zero; it does not
authorize individual non-empty absence query/proof identities.

The cutoff-only form now derives the same commitment before checkpoint
execution. Runtime receipts retain exact fee/event facts, a checkpoint-specific
validator recomputes the native ordered roots, and a two-phase private
prepare/bind capability fixes the commitment before the native
`BlockHeader::id()`. The capability retains the strict-H1 certified height-27
parent and accepts only an authenticated execution transition, not a naked
post-state root. A subsequent crate-private wrapper exact-decodes and strictly
re-verifies raw checkpoint/two-seal/terminal/handoff evidence and re-runs B2-F;
the dedicated reason-0/reason-3 checkpoint-28 vector freezes that join under an
application-private replay seal. That seal is not a protocol aggregate proof,
and the first vector is deliberately empty/state-preserving rather than shared
evidence for non-empty runtime receipts. The independent Node gate recomputes
the H3a/H2 ICS23 evidence, native private seals, strict B2-E/B2-F composition,
descriptor/certificate, and both old/new role signatures and quorums. This
path also has an independent application-private SQLite checkpoint-preparation
sidecar. It uses WAL, `synchronous=FULL` and `BEGIN IMMEDIATE`; freezes one
transition binding plus `(transition, checkpoint kind, height, view)` slots;
allows exact reserve/bind replay; and sticky/durably halts on a changed binding
or a second value for an occupied slot. The crate-private durable reserve/bind
wrappers and a focused same-process reopen/conflict/corruption Rust suite have
landed. Replay rows are inert
comparison material and cannot restore an opaque authority. The path is still
not production-reachable: the sidecar is not wired to ABCI startup or a
complete Comet/native carrier/host, covers checkpoints only rather than the two
seal blocks, and is not a signer persist-before-sign journal. There is no live
seal proposal/vote/signing plumbing, and `request.hash` is never reinterpreted
as a native ID. Fields 13/14, epoch-anchor
activation, and an atomic Core epoch transition remain open. Field 12 governed-
upgrade authority remains a separate open object.

The active runtime profile has also frozen its no-failed-receipt policy. Its
opaque exhaustive taxonomy separates 21 deterministic transaction rejects
from 7 authenticated-state/internal invariant faults. Rejects invalidate the
whole block and return neither a receipt nor mutations; invariant faults are
fail-stop facts. Runtime `TryStateViewV0`/`try_execute_v0` now returns either a
successful receipt or an opaque real-attempt failure with no public
constructor. Its typed state-read error cannot collapse into a default object,
`TaskNotFound`, or a terminal runtime fact. A crate-private execution-outcome
adapter remains deliberately unwired: it consumes the authenticated execution
inputs into the real attempt and preserves the same opaque token in either the
success or failure result, eliminating a second same-generation join during
promotion. A typed state failure is returned unchanged and not terminalized, a
deterministic reject is promoted only from the token carried by that attempt,
and success produces only an `AppliedRuntimeAttemptV0`.
`Valid` still requires a roots-match capability that owns the applied attempt.
A typed self-head reader and an opaque, connection-owning authenticated runtime
snapshot have landed. Its one SQLite `BEGIN` transaction validates the store
bindings, canonical committed height and app hash, query floor, latest root
version, and exact head root; all keys are read from that same snapshot, and a
typed explicit `finish` ends it. Snapshot begin uses maintenance `try_lock`.
Core now privately freezes the exact positive-height parent header in each
payload-validation request. The production parent constructor consumes that
capability and opens only an exact committed-head height/root; synthetic
genesis is explicitly headerless and a speculative/non-head parent is typed
retryable source mismatch until a canonical overlay store exists. The general
host/ABCI runtime view remains unwired, while the bounded production validation
cursor owns a private `prior delta -> exact authenticated snapshot` fallible
view. Legacy `load_object` remains its prior direct read, and the ABCI outcome
policy is unchanged. Snapshot begin relies on the startup full scan for
future orphan value/node/stale-index rows; its pin spans only one cloned store
family, not independent handles or processes, and no external watermark or OS
lock exists. A legacy test-only inert regular-block traversal now freezes a narrower
ownership shape: it exact-compares retained header/body/parent/configuration,
binds the retained policy to the real test-store policy before opening the
parent snapshot, proves the validator-lifecycle leaf and physical singleton in
that same fixed snapshot, and joins its active-validator projection to the
retained native set. It internally walks raw outer body bytes in exact index order
while deriving target height and `BlockId` from the retained header. It can
finish only after complete traversal and successful snapshot finish; cursor
classification is available only by explicitly finishing the consumed
traversal, so finish errors outrank both incompleteness and cursor rejection;
Drop produces neither a classification nor a finished capability. Each
visited item is decoded from those exact outer bytes as a real
`SignedCommandEnvelopeV1`; the consensus-app helper uses dalek
`verify_strict` with the existing chain/header-time rules
against the exact signer list whose commitment is bound to the test store, and
the exact inner payload is decoded as `CanonicalTxV1` with payload-type,
sender, and nonce joins. Neither JSON layer is re-encoded as authority, and
signer-policy admission exact-decodes the Ed25519 point and rejects weak keys.
This is command-envelope-specific: generic `verify_hex`, vote/QC verification,
the live-node development oracle, and the PoCO `StrictEd25519Verifier` type are
unchanged. A chain with retained production history would need an explicit
app/protocol activation boundary for this narrower acceptance set.

A separate legacy test-only owning runtime session now consumes the same exact
header/body/parent/configuration bundle and authenticated snapshot. It derives
the runtime context from retained header and envelope facts, invokes the real
fallible `try_execute_v0` strictly in body order, and resolves reads through
the session's private changes before the fixed parent snapshot. Successful
runtime receipts are converted only to native receipt shape; each receipt's
mutations are staged on a cloned delta and must satisfy the exhaustive
account/task/fee/monetary canonical key/type/value relation plus unique-key,
immutable-type, expected-version, and exact-successor checks before that delta
replaces the session state. Task mutations also pass the runtime's complete
status/field-group/version/height validator through a separate opaque read-only
failure type. A two-transaction fixture proves the second transaction can
read the first transaction's delta. Reversed order, a deterministic second-
transaction rejection, a state-read failure, receipt conversion failure, or a
mutation invariant consumes the whole session and discards every prior change
and receipt. Success and failure both require explicit snapshot finish, whose
error takes precedence over an incomplete traversal or runtime/cursor cause.
After a failed snapshot finishes, one opaque non-cloneable value still owns the
exact block/configuration inputs, authenticated lifecycle, failed index, and
decoded observation/transaction together with the hidden cause; it accepts no
second input join and offers no standalone-cause conversion.

The successful legacy test-only path now performs a further bounded join. It encodes
the complete private delta, fully revalidates the fixed parent state on the
same still-open SQLite transaction, and plans exactly `parent + 1` without
calling the latest-head planner or accepting a caller target/root. Only after
the snapshot finishes successfully does one opaque finished value expose that
in-memory plan. A second by-value comparator rebuilds native receipts from the
retained raw body and real `RuntimeReceipt`s, hard-codes
`StrictEd25519Verifier`, and checks state, payload, receipts, and evidence roots
plus the retained validator set, parameters, and `BlockId`. Two-transaction and
empty-write positives, canonical state/receipt-root substitutions, and
planning/incompleteness versus finish-error precedence are non-ignored tests;
the query-only planning path leaves the committed height and app hash
unchanged. A same-path independent WAL writer control commits a competing
exact-next sibling after the session's first read and proves that later runtime
reads and planning remain on the original parent snapshot until finish.

The bounded production validation join now consumes the Core-issued exact body
and parent capability, loads the complete namespace-8 active validator set and
parameters plus validator lifecycle from the same still-open transaction, and
checks their mutual epoch/hash relation and header commitments before exact
body validation. No caller supplies a second parent, height, root, set, or
parameters; no cache or second connection participates. The joined carrier is
private, non-cloneable, non-serializable, and yields no fact if snapshot finish
fails. Foreign configuration/root splices and a sibling writer moving the
committed head are covered by non-ignored negatives. Its application payload is
staged through exact decode under the authenticated
`max_consensus_message_bytes`, then bound to the retained header root. Source
non-canonicity or payload/evidence-root mismatch remains `Unavailable`; only a
complete canonical, root-bound logical block above authenticated
`max_block_bytes` is `DeterministicallyInvalid`.

The Core request is retained first by a private owning open carrier. A host
failure before snapshot begin returns that exact owner directly. Once a
snapshot is open, source or body admission failure escapes only after close and
still owns the complete `ValidationId`, target block, and parent; material that
never passed admission is never represented as an authorized body. Snapshot-
finish failure replaces the pending source/invalid/invariant cause but retains
the Core owner. There is no constructor from a bare ID, generation, block,
parent, or cause, and no request from another generation can be joined to the
failure.

The original Core-issued `PayloadValidationRequest` and every `Clone` descended
from that same object graph share one process-local Arc-backed atomic one-shot
gate. Exactly one claimant in that graph may cross into the owning validation
carrier. A losing clone is suppressed or coalesced by the current private
native-admission branch before snapshot/source/body classification; that branch
returns no `Unavailable`, `DeterministicallyInvalid`, or `InvariantFault`
classification and emits no callback. The scope is not all requests with the
same complete `ValidationId`: independently started Cores from the same
obligation-free durable state may accept the same ingress and materialize
separate request/gate object graphs. The public Core `Input` API is not a
capability-gated callback path. Different generations remain independent, and
an old object graph remains suppressed after its one claim. The object-graph
gate alone remains process-local and is not a cross-instance or cross-restart
exactly-once protocol.

Core also privately binds `PayloadValidationRouteV0::Proposal` or
`PayloadValidationRouteV0::Synced` inside the request. Native app admission
consumes the complete `Effect` and verifies the outer
`ValidatePayload`/`ValidateSyncedPayload` wrapper against that inner route
before it may claim the object graph or read host state. A wrapper splice is a
transport invariant, does not consume a correctly wrapped clone, and is not a
duplicate, `Unavailable`, or `DeterministicallyInvalid` result. The exact route
travels with the owner through open/body/cursor/runtime/post-state/comparator
and process-local disposition; callers cannot inject a bool or naked route.

Separately from current application-store schema v8, Core `SafetyState` schema v5
introduced a canonically ordered `DurablePayloadValidationObligationV0` before
either `ValidatePayload` or `ValidateSyncedPayload` may escape a
`PersistSafetyState -> StorageAck` barrier. Each record binds the Core-selected
route, full `ValidationId`, exact `SignedProposalV0`, exact
`PayloadValidationParentV0`, and `first_recorded_revision`; the live invariant
also binds the generation to that first revision. `StorageAck` reconstructs a
request only from the durable record and its matching volatile proposal mirror.
Core `SafetyState` schema v6 added the separately sorted completion set, but
retained the process-local `ValidatedBlockCommitmentsV0` capability inside a
cloneable record. Schema v7 replaced that field with
`DurablePayloadValidationResultV1`: `Valid` stores only inert block ID, logical
size, transaction-count, and evidence-count comparison facts. There is no
conversion back to the live capability. Every direct or synced callback still
atomically replaces its exact obligation with a same-key completion before
persistence, and replay compares a newly supplied live result only after
projecting it into the same inert form. Reuse under the opposite route,
different source/owner facts, a different result, or different `Valid`
comparison facts is invariant or a typed integration conflict and cannot
overwrite the record. `Unavailable` closes only that generation, permitting a
later generation for the same block. These tombstones remain distinct from
block-ID-level terminal payload facts. Exact synced cancellation removes its
obligation without fabricating a completion; safety halt clears obligations
while retaining prior completions. Completion eviction remains disabled under
`completions + obligations <= max_observed_messages`. Current schema v8 also
freezes a pending SignIntent's first durable authorizing revision across
unrelated callback writes. Schemas v5 through v7 are rejected by
`Core::recover`; there is no implicit model-layer migration to v8.

Core bounds the complete signed-proposal durable resource -- logical block plus
exact certified-tail witness -- by authenticated
`max_consensus_message_bytes`. Its aggregate obligation budget additionally
counts the fixed route/ID/revision/parent facts and any exact parent header.
Ordinary `Core::recover` validates every schema-v8 obligation and inert
completion and then rejects a non-empty obligation set with `InvalidRecovery`;
that entry does not reissue pending validation. Safety-state schemas v5 through
v7 have no implicit migration. Completion-only ordinary recovery provides
durable exact-result suppression, but non-empty obligations remain fail-closed
there. The separate G1c one-obligation recovery session described below is the
only bounded authenticated-ticket exception, and only for a reconciled
deterministic-invalid result. These rules do not provide general crash replay,
callback exactly-once, type-level callback authority, or recovery liveness.

Core now also has one exact bounded `SafetyState` record codec v0, frozen only
for epoch-zero `SafetyState` schema v8. Its outer record binds the codec and
SafetyState schema versions, one configuration reference, the exact state
payload, and a domain-separated checksum. The configuration reference binds
the exact Core configuration, verifier-profile reference, codec-layout
reference, and host-selected record/blob limits. Nested QC references, timeout
certificates, certified headers, and finality proofs use exact CEV0 admission;
the trusted-Genesis variants accept only the unique epoch-zero Genesis QC
derived from that bound validator set, while epoch anchors fail closed. Decode
requires strict EOF and byte-identical canonical re-encoding and returns only
an inert `UnverifiedSafetyStateRecordV0`; callers must still pass its state to
`Core::validate_persisted_state_v0` for configuration, semantic, and
cryptographic validation. A conservative limit preflight derived from
`CoreConfig` must succeed before the context can encode or decode.

The standalone `trnm-consensus-safety-store` crate now wraps that codec in a
Linux-only, node-local SQLite journal schema v2. It is intentionally separate
from `ApplicationStore`, AppHash, application snapshots, and peer state-sync
replacement. Its immediate parent directory must already exist and be
owner-controlled before initialization. An interrupted first initialization is
fail-closed and requires operator cleanup of the partial journal namespace;
v2 does not auto-repair or resume it. Historical journal-v1/schema-v7 stores
are rejected without implicit migration. The journal pins that directory plus its
main database, persistent WAL, SHM, and lock sidecar; holds lifetime-exclusive
writer locks; requires SQLite WAL with `synchronous=FULL`; and performs exact
transactional readback. Metadata binds the exact Core configuration reference,
verifier profile, codec/schema versions, record/blob limits, database budget,
and transition-context codec. The active and previous revisions are retained
as one checksummed predecessor chain with independently audited accounting.
Two separately aligned checksummed head slots alternate `Stable` and
`HeadIntent` watermarks, so open can distinguish the exact pre-commit head from
its one-step target. A third one-way terminal-halt latch binds conflicts without
overwriting either head slot; every other database/sidecar combination fails closed.

Core persistence effects now carry an opaque `SafetyStatePersistenceV0`
request: only Core can bind its exact barrier and state. A process-local
binding identifies the host-designated Core instance; public Core clones
receive different affinities, while Core's private transactional steps preserve
the issuing affinity. A host adapter must verify that binding before passing
the request to the journal. The journal exact-decodes and semantically and
cryptographically validates every retained state and its successor relation.
Its returned head is still an inert fact: an obligation-bearing head can be
authenticated and reported as requiring replay, but `Core::recover` continues
to reject it.

This is not yet production host/effect-driver wiring, authenticated obligation
replay, full cross-crash takeover, or complete HotStuff SafetyRules/locked-QC
reconciliation. The separate signer journal provides durable canonical
`SignIntent` exact replay only behind injected signature-producer and external
monotonic-watermark interfaces; `trnm-poco-node` exposes neither as a production
adapter. The SafetyState journal alone cannot detect restoration of its complete
database/WAL/sidecar namespace, and the signer journal's external watermark has
no production implementation. Safety journal v2 is not certified for NFS, SMB,
FUSE, overlay filesystems, fork-after-open, or an untrusted same-EUID process.
Neither store establishes process-wide Core uniqueness.

After that wrapper/route check and process-local claim, and before any host or
snapshot read, historical application-store schema v6 durably reserved one
`validation_jobs_v0` row for `(route, full ValidationId)` under
`BEGIN IMMEDIATE`. The row freezes the raw target header, a strict versioned
payload/evidence body record, parent tip and optional exact parent state,
execution-configuration references, the currently generation-derived creation
revision, the existing raw-source fingerprint, and domain-separated body/
immutable/row checksums. It starts in `reserved`; v6 accepts only that state and
an empty `validation_callback_outbox_v0`. Application-store schema v7 preserves
all verified v6 reservations and activates exactly one later state:
`callback_pending` for a complete mixed-body computed state-root or receipts-root
mismatch. A consuming owner-bound bridge maps only those two mismatches to stable
reason codes 1 and 2. One `BEGIN IMMEDIATE` transaction writes the fixed 120-byte
`trnm.native-validation.invalid-artifact.v0` artifact, the fixed 84-byte
`trnm.native-validation.invalid-callback.v0` payload, their domain-separated
checksums and idempotency key, the unique outbox row, the job state, and O(1)
accounting. A pre-commit error rolls all of them back and returns the unique
prepared owner. `Valid`, `Evaluated`, `Delivered`, `Acked`, `Applied`,
`Unavailable`, and invariant results remain inactive and fail closed in v7.

Current application-store schema v8 preserves every verified v7 `reserved` and
`callback_pending` row and activates two later deterministic-invalid delivery
states plus their app-private writable transitions.
A `delivered` row must retain its congruent outbox with a canonical delivery
attempt of at least one; the accepted-Core revision and payload-checksum fields
must still be absent. An `acked` row must have retired that outbox and its
outbox accounting, must bind an accepted Core revision later than the job's
creation revision, and must bind the rederived canonical invalid-callback
payload checksum. Both states use the domain-separated delivery-row checksum.
`evaluated`, `applied`, every `Valid` result, every other invalid reason,
`Unavailable`, and invariant results remain inactive and fail closed in v8.
The first successful deterministic-invalid seal retains a non-cloneable live
owner that inert reopen/recovery facts cannot recreate. An app-private
non-cloneable driver fixes one designated store, one owned Core instance, and
one injected safety sink for the whole process-local phase chain. It calls the
real route-specific
`Core::step`, accepts only the opaque persistence request issued by that
designated Core and its exact barrier/state, marks
the callback `delivered`, confirms that exact state through the same sink,
marks it `acked`, and only then submits the matching `StorageAck`. The driver
does not accept completion-only replay: the current Core completion tombstone
does not bind the artifact/callback checksum, so an empty-effect completion
cannot authorize a durable artifact. After `StorageAck`, an unchanged Core
state and either no effect or the exact expected `SafetyHalted` effect are
required.

G1c adds a separate existing-only recovery facade without weakening ordinary
startup. `Core::recover` still rejects every non-empty durable-obligation set.
The only alternative is an inert, non-cloneable session for exactly one
obligation; no live Core is exposed until a trusted reconciler matches the
complete challenge to a deeply verified application row that is already
`DeterministicallyInvalid`. More than one obligation, a different result, or a
missing/mismatched row fails closed.

The schema-v8 recovery facade admits only existing `CallbackPending`,
`Delivered`, and `Acked` deterministic-invalid rows. It never creates a
reservation or runs fresh execution, and it rejects `Reserved`, `Evaluated`,
`Applied`, `Valid`, `Unavailable`, and unknown state/result tags at open. It
retains recovered transition owners internally rather than reconstructing a
general callback token from inert row bytes.

The standalone SafetyStore supplies the concrete, non-cloneable
`ConfirmedNativeDeterministicInvalidHeadV0` exact-readback token. Only the
store's complete authenticated `head()` path can construct it. Its state,
context, transition, revision, and checksums are read-only facts; it has no
public constructor/parts conversion and implements no application or Core
authority trait. The production application recovery API accepts only this
concrete token and validates its issuing journal/profile; the node obtains
those expected values from the SafetyStore it actually owns rather than from a
detached caller projection. Before the first supported application recovery
row is created, the test-only bootstrap writes a fixed 140-byte, checksummed,
create-once manifest beside the App database. It binds the App host
configuration to that Safety journal/profile, is synced with its parent, and
is opened and identity/byte-pinned before recovery. A missing, replaced,
tampered, or newly nominated binding fails closed. This local manifest is not
included in application state snapshots.

The token is not standalone or general transition authority. It becomes one
necessary input to the bounded `C+D`/`C+K` application transition only when the
pinned manifest names its issuing journal/profile and the facade independently
matches the exact existing `Delivered`/`Acked` row and full transition lineage.

The inert `trnm-poco-node` recovery host joins three existing stores using the
bounded matrix `O+P`, `O+D`, `C+D`, and `C+K`: obligation plus
`CallbackPending`, obligation plus `Delivered`, completion plus `Delivered`, or
completion plus `Acked`. Every other active-count/context/status combination
fails closed. A successful join only returns a bootstrapped inert owner; it
does not sign, broadcast, schedule, or make the package deployable.

An exact reopen returns its checksum-verified durable state rather than silently
coalescing unfinished work, while no reopen can recreate the unique first-
reservation token. Startup and recovery exact-decode and canonically re-encode
the target and any present parent header, rebind identity/parent/configuration
fields, rederive the frozen
raw-source fingerprint, and enumerate verified rows in canonical state/identity
order. Malformed framing, semantic splice, checksum drift, accounting drift,
or host/runtime reference drift fails closed. A headerless height-zero parent
is only a structurally revalidated inert recovery fact: it must bind an
epoch-zero regular height-one target to the target genesis hash, while trusted
genesis timestamp/hash authority remains Core-owned until a later takeover
rebinds it. The journal remains bounded by
65,536 rows and a 512-MiB aggregate raw-request budget. Reservation uses an
atomically maintained O(1) accounting singleton while startup independently
audits it against the real rows; exact reopen precedes capacity rejection. The
application compatibility boundary also requires `max_block_bytes <= 16 MiB`.
Schema-v5 migration succeeds only when its legacy reservation table is empty;
a non-empty v5 table is unreplayable and rolls back unchanged. Startup and
snapshot installation advance explicitly through `v3 -> v4 -> v5 -> v6 ->
v7 -> v8`; every migration step has its own `BEGIN IMMEDIATE` atomic boundary
and writes only its fixed successor version. The v6-to-v7 activation validates
every reserved row, foreign key, binding, resource bound, and accounting fact
and rolls back to v6 on any drift. The metadata-only v7-to-v8 activation first
deep-validates the complete v7 reserved/callback-pending journal and rolls back
to v7 byte-for-byte on any incompatible state, outbox, checksum, binding, or
accounting fact.
State-sync
snapshot generation scrubs outbox rows first and jobs second only from the
temporary copy and verifies both are empty, leaving the source database
unchanged; installation refuses to overwrite a non-empty target-local
validation journal. This is a revalidatable raw request/recovery-fact foundation
plus a bounded deterministic-invalid G1c takeover/join. It is not a
reconstruction of the signed proposal witness, a durable `Valid` artifact, a
fresh executor, a BlockId-keyed speculative overlay, an ordered finalization
queue, or a general application recovery protocol. There is no production
effect driver, authenticated network, state-sync recovery join, complete
production crash matrix, process-wide Core uniqueness, or callback exactly-once
guarantee. The feature-gated G1e harness inserts an observer into the official
existing-only host and exercises sixteen real SIGKILL checkpoints: `O+P`,
`O+D`, `C+D`, and `C+K` across both routes and both supported
deterministic-invalid reasons. An authentic feature-only fixture seeds `O+P`;
the host authenticates and observes that boundary, then drives
`P -> D -> C -> K` to reach the other three states. A fresh process
authenticates and recovers the exact journals after each kill. The `O+P` cases
are recovery-from-preseeded-state evidence, not host-creation evidence.
This is local Linux process-termination evidence, not power-loss, host-reboot,
device-write-cache, or hardware-fsync evidence.
The application recovery facade takes the exclusive side of the
ordinary-shared/recovery-exclusive sidecar lock, pins its PID and canonical
parent/lock/main-database/manifest identities, and audits the complete
supported/active row set before joining. Parent, main database, lock, manifest,
and existing WAL/SHM objects must have the expected owner and may not be
group/world writable; all three store parents must be canonical, distinct, and
non-nested. WAL/SHM inode lifecycles remain SQLite-managed, and a hostile
same-EUID process remains outside this local Linux contract. The non-default
`recovery-test-support` fixture may bootstrap `P` only for dedicated recovery
tests. The SIGKILL helper and its filesystem watermark additionally require
`recovery-process-test-support`; development library artifacts build with
`--no-default-features` and record that both test surfaces are absent.
Whole-namespace rollback/clone safety still depends on a production independent
monotonic boundary that is not implemented here.

That carrier now also opens a production, process-local sequential transaction
cursor. Its host tuple can only be borrowed from initialized `AppCore`; the
canonical signer-policy preimage must match store metadata and the
snapshot-authenticated lifecycle. The cursor obtains the index and outer bytes
only from the retained body, strictly verifies the exact envelope, exact-decodes
and validates the inner `CanonicalTxV1`, joins sender and nonce, and derives
height, native `BlockId`, header time, signer id/role, and inner-byte length.
The prepared transaction continues to own the cursor and open snapshot. No
production API can seek, repeat, skip, split it into parts, or supply a second
tx/index/context/view. A closed decode failure retains the authorized owner,
next index, private delta, and already-applied receipts. One consuming attempt
then invokes the real fallible runtime over `prior delta -> that same
snapshot`; only successful native-receipt conversion and atomic validation/
staging of every mutation return the cursor at the next internal index. Any
runtime, typed state-read, receipt-conversion, or mutation-invariant failure
destroys all prior delta/receipts but retains the authorized owner, failed
index, exact outer/inner bytes, decoded transaction, and derived context. In
either stage a finish error replaces the pending cause without losing that
exact owner. A non-runtime payload instead retains its exact bytes, verified
envelope/context, cursor, and snapshot as an opaque routing carrier; it neither
advances nor becomes terminal invalid.

This is still not terminal production execution authority. The production
cursor can perform real runtime attempts plus owner-bound successive
PoCO/validator attempts, family-local sealing, and success-only advance. Before
planning a complete runtime-only body, it replays each retained real
`RuntimeReceipt` mutation set separately and sequentially against the same
authenticated snapshot. A key may recur in different transactions only when
the expected/next object versions form one continuous chain; a duplicate key
inside one receipt is invalid. The receipt-only final map must exactly match
the cursor delta, and JMT writes are derived only from that replayed map for the
unique exact-next update. That plan is paired with an opaque process-local seal
covering its version, root, nodes, values, stale-node indices, and key
preimages. The snapshot closes before the sealed inert finished plan can
escape. Incomplete-body, receipt-replay, authenticated-read, and planning
failure likewise close into one value retaining the authorized owner, next
index, delta, and applied receipts. If finish fails, it replaces the pending
plan cause and discards any computed plan/seal, but retains those ownership
facts. A single consuming comparator rebinds retained receipt -> replayed
delta -> exact plan, verifies the full seal before any root mismatch, rebuilds
native receipts, and hard-codes strict Ed25519 for static ordinary commitments.
Root computation, seal, or other post-authorization payload/evidence, static-
commitment, `BlockId`, provenance, or internal drift is invariant/fail-stop. Its
process-local owning classification is limited to `Valid`,
`DeterministicallyInvalid(State|Receipts)`, or `InvariantFault`, with the
complete owner retained in every branch; `SourceUnavailable` is resolved at
source admission and structurally cannot enter the comparator. A consuming
private bridge now promotes only that owner into the app-private
`ExecutionOutcomeV0`: `Valid` derives its generation from the retained Core
request, computed root mismatches become whole-block no-receipt invalidity, and
comparator drift becomes fail-stop while retaining the failed plan. A second
private consuming carrier derives the exact route/full `ValidationId`, result,
and valid commitments from that outcome and can form only the corresponding
`PayloadValidated` or `SyncedPayloadValidated` Core `Input`; an invariant fault
cannot form an input. This legacy runtime-only carrier is type-level callback
material only: it does not itself call `Core::step`, persist or deliver an
outbox, or provide
`AuthorizedNativeCheckpointExecutionV0`, checkpoint, or ABCI authority. The
pre-terminal failure carriers share that private,
non-cloneable, non-serializable, no-parts/no-standalone-cause boundary.
Successive PoCO/validator items now use that same owning cursor: exact prior
non-runtime provenance stays private, PoCO continues from one evolving unsealed
overlay, validator scheduling continues from the staged lifecycle, each latest
whole-prefix plan/write replaces its predecessor, and the internal index moves
only after execution plus sealing succeed. This remains open-snapshot staged
execution until the whole body is consumed. A distinct owner-bound planner then
rebinds the complete cursor provenance, merges the replayed runtime final delta
with only the final replace-only PoCO prefix writes or the no-PoCO scheduled-
cutoff manifest refresh plus the final explicit or `prepare_height(target)`-
implicit validator singleton, and rejects duplicate raw keys and key hashes.
It produces and seals exactly one exact-next JMT plan on that same snapshot;
snapshot finish is mandatory and overrides/discards any pending planning cause
or successful plan. The planning carrier remains inert. A distinct consuming
comparator now rebinds every mixed-body item and final state source, rebuilds
one receipt per body item in exact index order, rederives the merged writes,
verifies the retained plan/seal plus strict ordinary commitments, and
classifies only state then receipts mismatches as deterministic. Runtime
receipts preserve real gas, exact `u128` fees, and ordered events; PoCO and
validator items use the frozen empty internal receipt, while cutoff refresh and
implicit validator activation add no body receipt. The result is still only a
private matched/failed/classified owner, not an app-private `Valid` outcome.
Plan application/persistence and head update, a durable `Valid` artifact/outbox,
speculative-parent overlays, cross-epoch/handoff, production host/Core wiring,
ABCI wiring, and cross-process rollback protection remain hard open
prerequisites before the general terminal/Core callback path. The
deterministic-invalid state/receipts-root slice alone now has a process-local
real-Core driver integration; the object-graph gate itself performs no
terminal mapping, and only the current private admission branch is proven not
to emit a callback for a losing clone.
The legacy private route-bearing outcome bridge proves that `Proposal` maps
only to `PayloadValidated` and `Synced` only to
`SyncedPayloadValidated`, but it does not itself submit that input to a Core
instance or establish callback delivery.
Neither the v7 invalid journal nor the v8 delivery-state activation stores an
evaluated `Valid` artifact, durable JMT plan, or `Valid` callback outbox. V8
adds process-local invalid delivery writers, a non-cloneable live owner, and
real Core callback/barrier execution behind an app-private driver, but its
injected sink is only a test boundary and is not wired to the standalone
SafetyState journal. A private inert durable-plan codec now covers the exact
persistence-bearing JMT
version/root, nodes, values, stale indices, and key preimages without exposing
the process-local plan seal or serializing `TreeUpdateBatch` as a container.
Its per-node representation is explicitly pinned to the existing
`jmt-sha256-0.12.0-node-borsh-v0` store adapter. Decode produces only bounded
unverified bytes. Exact-parent/root and exact-next replanning from canonical
writes produce only an inert verified carrier, so recovery can still verify
an artifact after another fork occupies that state version. A separate
consuming boundary retains and rebinds the original parent root, requires an
unoccupied target, replans the same writes on the current reader, and releases
the fresh `PlannedAuthUpdate` only if its physical bytes are still exact. The
codec is not yet embedded in a `Valid` evaluated artifact or written to the job
table. A future activation must first prove the 64 MiB physical-plan envelope
against the consensus block/write scale gate; exceeding a local artifact budget
can never
become deterministic invalidity. The remaining `Valid` validation-time atomic
boundary must persist a versioned revalidatable artifact together with
callback-outbox intent; a distinct
Finalize-time atomic boundary must revalidate the exact authority and couple
JMT/domain apply, root/native-head persistence, head advancement, and applied
state. Neither the `Valid` validation-time nor the Finalize-time boundary is
implemented. General authenticated replay tickets and completion retirement
after durable
host-delivery acknowledgement, speculative-parent/BlockTree reconstruction,
application-reservation takeover, `Valid` evaluated-artifact persistence,
production callback scheduling/delivery, recovery for outcomes outside the G1c
deterministic-invalid matrix, crash takeover outside the bounded G1e SIGKILL
matrix, completion-only artifact replay, and callback exactly-once are also not
implemented. The current
process-local invalid driver uses Core's `StorageAck` cleanup barrier only
after its injected sink and application `acked` transition; that test boundary
is not a production host callback-outbox acknowledgement. The separate inert
G1c node join does not make that first-seal path a general SafetyState adapter.
Snapshot-closed real runtime-attempt failures now have a separate owning bridge
into the same outcome kernel. It uses only the opaque runtime attempt's stable
disposition and the exhaustive typed authenticated-read variants: transaction
reject becomes whole-block invalid, typed dependency/source loss remains
`Unavailable`, and runtime/state/host/receipt/mutation invariants fail stop.
The complete failed attempt remains retained. Open, reservation, body/decode,
and post-state failures now have matching exhaustive owner-derived mappings:
typed dependency/source/capacity loss remains `Unavailable`, verified evidence
or transaction encoding/authorization failure becomes whole-block invalid, and
internal/authenticated drift fails stop. Every mapped outcome retains its exact
failed owner and none emits a Core input. A consuming closed-set non-runtime
dispatcher now derives only PoCO application, validator transition, or
unsupported from the exact verified envelope while retaining its cursor and
snapshot. A second consuming carrier strictly decodes canonical PoCO operations
and validator transitions, binds the retained target-height or
schema/chain/command/operator facts, and retains the exact family owner on
failure. A further consuming attempt constructs the first PoCO authority state
only from the pinned authenticated projection and schedules the first validator
transition only against the retained authenticated lifecycle; later same-block
operations continue from the cursor's evolving PoCO overlay or staged validator
lifecycle. It accepts no supplied projection/lifecycle loader and rebinds
decoded PoCO values to their exact raw bytes. Semantic/family failures
explicitly finish the owned snapshot before
exposing a closed owner, with finish failure taking priority. Authenticated
source loss and independently proven authorization rejects are typed. Validator
scheduling now has closed deterministic/invariant reasons, checked nonce/delay
arithmetic, and clone-and-swap postcondition validation. PoCO application now
has its own closed apply reason set for raw ownership, height/revision,
capacity/duplicate, nullifier proof, validator rules, validator PoP, and signed
semantic changes. Authenticated negative facts reject deterministically;
present-but-malformed companions, malformed authenticated predecessors, and
derived CAS/mutation postconditions fail stop. Decision-ID and cap/window
failures reject deterministically, while counter/epoch/retention arithmetic
exhaustion is invariant. Nullifier classification distinguishes malformed
count/family/id/encoding or proof-key shape from a correctly key-bound proof
rejected by the authenticated root; both are deterministic, while authenticated
accumulator-count exhaustion fails stop as a protocol-counter invariant;
consumer-key authorize/revoke preserves nested typed failures, maps remaining
signed shape/height/semantic faults to deterministic semantic rejection, and
maps an authenticated negative key lookup to deterministic missing-fact;
revocation also binds the signed logical key to the body identity, fails stop
on a present active-predecessor/key-authority divergence, and leaves malformed
signed revoked successors deterministic;
consumer-key prune now carries the exact full row, raw semantic owner, all
kind-2/kind-3 source bytes and the family-11 subject across capacity admission.
Its consumer `-1` and nonce `-N` caps precede unsupported fields; terminal/
retention/reference checks precede authenticated companions and the signed
all-delete set; counter exhaustion precedes late proof verification. The
family-11 digest includes canonical consumer/key identity plus the ordered
watermark row, so two empty rows remain independently prunable. Carrier drift
fails stop before proof, and proof succeeds before exact slot/leaf deletion.
The real nonempty-watermark fixture and two-empty-row regression close only the
isolated handler/audit surface, not production cross-epoch reachability;
meter definition preserves nested typed errors and separates deterministic
signed policy/semantic shape from deterministic active-parameter cap rejection.
`DefineMeterPolicy` now carries one shared prepared policy/semantic transition
from capacity admission into execution: structural block/raw/aggregate bounds,
exact owner/context/revision/replay and cheap field admission remain first;
signed preparation and authenticated nullifier-count arithmetic precede the
family and defensive-total record caps; late nullifier-root verification and
mutation occur only on the cloned candidate after those caps. Saturated and
cap-minus-one collision tests freeze cheap-field/signed/counter rejection
before record caps, record caps before late root rejection, and full-overlay
rollback. The same closure now also covers consumer-key authorization and fund
settlement below. `RetireMeterPolicy` now carries one zero-delta prepared
replacement across that boundary: canonical ID/slot and every
unchanged family/total cap precede unsupported fields, target height/decision,
full policy validity, already-retired state, authenticated kind-5 predecessor,
signed successor, and count `+1`. The carrier freezes the complete source and
successor policy rows, slot, decision/raw semantic owners, and source bytes;
carrier CAS runs before the one late family-4 proof, then exact row/semantic
replacement. A real two-block four-policy fixture proves sorted `4 -> 4`,
three byte-exact untouched rows, revision/count `+1`, and seal. Synthetic fifth
rows remain handler-boundary priority evidence and shared vectors stay
unchanged. `PruneRetiredMeter` now carries its own prepared meter `-1` and
kind-5 delete across the same boundary. Canonical ID/slot and all family/total
caps precede unsupported fields, then full policy, strict retention,
active-certificate and retained-usage exclusion, authenticated predecessor,
and the signed exact single-delete set. The certificate scan rebinds all
body-derived authority owner fields, including meter ID/version, to the
authenticated kind-1 payload. The carrier freezes the complete policy row/
slot, raw semantic and field owners, and exact source bytes before row/leaf
deletion. It authorizes no new proof or accumulator increment: the permanent
family-12 identity inserted by meter definition remains occupied. A real
four-definition, one-retirement, isolated H284 fixture proves sorted
authenticated `4 -> 3`, exact deletion,
three untouched rows, unchanged accumulator, and seal; a separate real
accepted-certificate fixture proves reference rejection. One synthetic six-row
`6 -> 5` cap collision remains handler-boundary evidence and shared meter-prune
bytes remain unchanged. This closes only the isolated handler/audit surface,
not production cross-epoch reachability, Core activation, host integration, or
a phase. Every other audit-open family still needs its own capacity-order audit
before terminal failure mapping.
Meter prune rejects a missing authority policy as a pre-clone negative fact;
meter retirement distinguishes signed ID/height/next-state rejection, missing or
already-retired authority, and authenticated old-fact/authority divergence;
meter prune validates signed IDs before policy lookup, separates nullifier and
active/retention/reference rejection, and fails stop on authenticated retention
arithmetic or certificate decoding;
fund settlement maps its remaining signed certificate/commitment/units and
semantic-shape failures deterministically while preserving nested typed
nullifier/counter/CAS reasons. It now carries one prepared reservation and
semantic transition through capacity admission: structural and exact owner/
context/revision/replay checks remain first; signed ID/commitment/units/semantic
preparation plus authenticated duplicate checks and insertion-count arithmetic precede reservation
and defensive-total record caps; certificate-absence and settlement-decision
proofs plus all mutation remain late on the cloned candidate. Saturated/cap-
minus-one collisions freeze those boundaries and full-overlay rollback;
consumer-key authorization likewise carries one prepared authority/semantic
transition through capacity admission. Structural and exact owner/context/
revision/replay plus cheap unsupported-field admission remain first; signed
height/ID/key/derived-decision and exact-create semantic preparation with
authenticated nullifier-count `+2` precede the consumer-key and defensive-total
record caps. Both insertion proofs and all authority/semantic mutation remain
late on the cloned candidate. Canonical H1 apply/seal plus saturated/cap-minus-
one collisions cover signed/authenticated, proof count/family/ID/root, counter,
structural, body/carrier and full-overlay rollback boundaries; proof-key and
encoding faults remain decode-first. Consumer-key revocation now has the
corresponding closed zero-delta replacement path. Structural and exact owner/
context/revision/replay checks, canonical consumer/key IDs, and exact authority-
slot presence precede the consumer-key and defensive-total record caps. At the
legal full four-record boundary those caps pass; unsupported fields, target
height/public key/derived decision, authenticated full-row/predecessor
agreement, signed revoked successor preparation, and accumulator count `+1`
then run before clone. The prepared carrier freezes the complete source and
successor rows, exact slot, raw semantic owner, family-2 decision nullifier,
and prepared semantic CAS. Only proof verification, slot replacement, and
semantic mutation remain clone-late. A real three-block test authorizes and
commits four distinct keys, accepts one certificate to create a nonempty
target nonce watermark, then revokes that row from the authenticated following
block, proving sorted 4-to-4, count `+1`, kind-2 revision `+1`, watermark and
untouched-row preservation, and seal. Its collision matrix covers shallow ID/
missing facts, the family cap, unsupported/signed/authenticated/counter
failures, proof count/family/ID/root, structural bounds, raw-semantic-owner/
carrier/source-watermark drift, and full rollback. Defensive-total arithmetic
remains in shared capacity preflight rather than an independently reachable
revocation collision. A synthetic fifth row is explicitly an unreachable handler-
boundary cap witness, not authenticated success evidence; proof-key/encoding
faults remain decode-first and frozen shared vectors stay byte-identical. The
same closure also extends to open challenge and release settlement below;
release settlement now carries one exact funded-unused reservation/delete
transition across capacity admission. Structural and exact owner/context/
revision/replay plus signed certificate ID and exact reservation lookup precede
the reservation-family `-1` and defensive-total record caps. After those caps,
unsupported-field rejection, derived decision, one exact kind-6 delete with
authenticated reservation/settlement agreement, and accumulator count `+2`
construct the carrier. It freezes the exact slot/value, family-1 certificate
and family-3 settlement-decision subjects, and semantic delete; only the two
chained proofs, reservation removal, and delete mutation remain clone-late.
Cross-family, same-family body, and slot drift fail as derived postconditions.
A real two-block fixture funds and commits four reservations, then releases one
from the authenticated next block, proving 4-to-3, count `+2`, kind-6 deletion,
and seal. Its collision matrix covers signed/missing/unsupported/decision/
authenticated/counter, both proof positions, structural bounds, carrier
binding, and full rollback. Frozen `release_refund_replay` H2 bytes and H3
resurrection rejection remain unchanged; raw proof-key/encoding faults remain
decode-first;
open challenge now carries one prepared pending record, challenge nullifier,
and lifecycle semantic transition through capacity admission. Structural and
exact owner/context/revision/replay plus cheap unsupported-field admission stay
first; signed/derived decisions, active-certificate/lifecycle/duplicate joins,
window and exact semantic preparation, and authenticated nullifier-count `+1`
precede pending-challenge and defensive-total record caps. The insertion proof
and all pending/semantic mutation stay late on the cloned candidate. Missing,
malformed, or divergent authenticated lifecycle companions fail stop before a
valid duplicate rejects as protocol; proof-key and encoding faults remain
decode-first. The canonical H3 exact vector still applies and seals once.
Saturated/cap-minus-one collisions freeze signed/authenticated, counter, cap-
versus-proof count/family/ID/root, structural, body/carrier, sorting, exact-
boundary and full-overlay rollback behavior. Their injected unrelated pending
rows omit matching certificate, semantic and nullifier provenance, so these
are handler-boundary fixtures only and the success case is not sealable or
authenticated end to end. Future-candidate registration deliberately keeps the
schema's bound-before-cryptography rule: structural and exact owner/context/
revision/replay plus validator-ID/duplicate admission precede future-family and
defensive-total record caps. Only after those caps, but still before clone,
come unsupported-field and authenticated nullifier-count `+2` bounds, checked
successor epoch/target, exact strict PoP, active projection/predecessor/history/
key joins, derived decision, and construction of one prepared record. The two
insertion proofs and sorted record mutation stay late on the cloned candidate.
A test-only authoring path builds four distinct exact successor-epoch
registrations from authenticated epoch-zero configuration: the fifth rejects
at cap even with later PoP/field/counter/proof faults, while the fourth from
three succeeds, advances the count by two, remains sorted, and seals. H22's two
changed/new canonical operations remain the frozen shared-vector witness, not
the cap witness; raw nullifier proof-key and encoding faults remain decode-
first. Validator registration now also has a closed capacity order: exact
validator-ID/history absence and one canonical active kind-9 create bound to
the body identity and a fresh key retain their frozen pre-cap priority. That
admission exact-decodes the embedded PoP structure but does not verify its
signature; the schema's cryptographic-work boundary here covers strict
Ed25519 and SMT proof verification. History/defensive-total record caps then
precede accumulator count `+2`, epoch/decision/CAS/strict-PoP preparation, and
one prepared history record. Clone-and-swap retains only one identity-absence
proof, two chained insertion proofs, and history/semantic mutation. Four real
active-epoch registrations authored from authenticated epoch-zero state freeze
the 4-to-5 cap and sealable 3-to-4 boundary. H1 and register/rotate vectors stay
unchanged. Validator rotation now has its own closed replacement path. Its
shallow exact validator-ID/active-kind-9/body-identity/fresh-key admission stays
before the family and defensive-total caps, but performs no strict signature
verification. A full four-record history remains legal because rotation has
zero record delta. After the caps, unsupported-field admission, active-
certificate exclusion, exact history lookup, revoked-history rejection,
retired-key count `+1`, accumulator count `+2`, epoch, decision, semantic CAS,
strict PoP/nonce, and predecessor head/nonce/history agreement are frozen in
that order. The prepared carrier retains the replacement record and exact slot,
two nullifier subjects, and semantic change; only chained insertion proofs and
mutation run on the clone. A real two-block test commits four registrations,
then rotates at the full bound from the authenticated next block, preserving
length/sort order, advancing count by two, and sealing once. Its collision
matrix covers unsupported fields, active references, missing/revoked history,
both counter priorities, epoch/decision/CAS/PoP/predecessor, late proof shape/
subject/root, structural bounds, body/carrier mismatch, and full rollback. The
compound active-reference collision is an authority-only handler-boundary
priority witness, not another authenticated success fixture. H1 and register/
rotate H2 bytes remain unchanged. Validator revocation now has a separate
closed zero-delta path. Canonical validator ID and exact history slot precede
all unchanged family/total caps. Unsupported fields then precede authenticated
kind-1 owner rebinding and active-reference exclusion, the derived revocation
decision, complete history/head and revocation provenance, already-revoked
rejection, an independent kind-9 predecessor join, the exact signed
active-to-revoked successor, and accumulator count `+2`. The carrier freezes
the complete source/successor rows and slot, both nullifier field owners, raw
semantic owner, two subjects, and exact kind-9 source CAS. Carrier drift fails
before the two chained proofs; row and semantic replacement occur only after
both proofs. A real H1 four-registration/H2 revoke fixture proves authenticated
sorted `4 -> 4`, three byte-exact rows, preserved key/nonce/PoP, count `+2`, and
seal. Separate real fixtures cover active-reference and already-revoked
rejection; same-block distinct-raw re-revocation remains a protocol reject,
while register-then-revoke reaches the deterministic one-mutation validator
rule. A synthetic fifth history is only handler-boundary priority evidence.
Shared validator-prune bytes remain unchanged and are not cross-
language `RevokeValidator` evidence. This closes only the isolated handler/
audit surface, not validator-history prune, production epoch/Core/host
reachability, terminal mapping, or a phase. Revoked-validator history prune now
has its own isolated decrement/delete closure. Canonical validator ID and exact
history slot precede history `-1`, every other family cap, and the defensive
total. No-proof admission then precedes complete history/head/revocation
provenance, revoked and strict-retention checks, authenticated certificate
owner/reference exclusion, the independent exact revoked kind-9 companion, and
the signed single delete. The carrier freezes the complete row/slot, both proof-
field owners, raw semantic owner, and exact source bytes before row/leaf
deletion. Permanent validator identity and consensus-key nullifiers remain
occupied, so the accumulator is unchanged. A real H1 four-registration/H2
revoke source rejects exact-boundary H282 and seals first-after H283 as sorted
authenticated `4 -> 3`, preserving three byte-exact rows. The active-reference
case uses a real certificate body but remains handler-boundary evidence because
revoked-provider/active-certificate coexistence is not authenticated-reachable;
the synthetic six-row `6 -> 5` cap collision is likewise not authenticated
state. Shared validator-prune bytes remain unchanged and prove only the
isolated register/revoke/wait/prune plus permanent-identity resurrection guard,
not the full-capacity carrier matrix or production epoch reachability. This is
not Core activation, host integration, terminal mapping, durable-node closure,
or a phase. Expired-certificate prune now has its isolated decrement/five-
delete closure. Canonical certificate ID and exact active row precede
certificate `-1`, all other family caps, and the defensive total. Unsupported
fields then precede exact certificate-body ownership and the independently
derived certificate/tuple/consumed-settlement/measurement/pending-aware-
lifecycle retained set. Strict stored-boundary and pending/reservation guards,
the exact signed five deletes, and checked accumulator `+2` remain pre-clone.
The carrier freezes the complete row/slot, both proof-field owners, raw
semantic owner, two permanent subjects, and all five source bytes; only the two
chained proofs and prepared removals run on the candidate. A real H1 sixteen-
operation/H2 four-accept chain rejects exact-boundary H282 and seals first-
after H283 as sorted authenticated `4 -> 3`, preserving three byte-exact rows
and unrelated nonce/usage owners while deleting exactly five leaves and
advancing count by two. A real H3 open challenge stays pending past retention
and rejects with its `ChallengePending` companion intact. Same-ID reservation
coexistence and the synthetic six-row `6 -> 5` cap collision remain handler-
boundary evidence only. Shared certificate-prune bytes remain the single
rejected-lifecycle replay, not the full-capacity/carrier matrix. The prune
handler rebinds retained body/five-leaf owners, not every acceptance-era
consumer, meter, provider, relationship, parameter, or signature join. The
isolated epoch-28 bootstrap is not production cross-epoch activation,
Core/host integration, terminal mapping, durable-node closure, or a phase.
Capacity-order closure is now
limited to `DefineMeterPolicy`, `RetireMeterPolicy`, `PruneRetiredMeter`,
`FundSettlement`, `AuthorizeConsumerKey`,
`RevokeConsumerKey`,
`PruneRevokedConsumerKey`,
`OpenChallenge`, `ReleaseSettlement`, `ResolveChallenge`,
`ProposeGovernance`, `ApproveGovernance`, `RegisterFutureCandidate`,
`RegisterValidator`, `RotateValidator`, `RevokeValidator`,
`PruneRevokedValidatorHistory`, and `PruneExpiredCertificate`; every other
family stays audit-open before terminal failure mapping;
resolve challenge now freezes the exact pending/certificate rows and indices,
target lifecycle/height/decision, challenge-decision nullifier, and semantic
transition before clone. Signed IDs, pending identity, and accepted-certificate
presence precede pending-family `-1` and defensive-total caps; unsupported
fields, decision, semantic/window checks, and accumulator count `+1` follow.
Only proof verification and prepared removal/lifecycle/semantic mutation run on
the clone. A real four-block fixture fills both pending slots and resolves one
from the authenticated next block, proving 2-to-1, count `+1`, terminal
certificate state, and seal; rejected and sustained shared vectors remain
unchanged. Collision coverage freezes signed/pending/certificate, cap,
unsupported-field, decision/window/semantic/counter, proof, structural,
carrier/source-row, and rollback priorities; raw proof-key/encoding faults stay
decode-first;
governance proposal now freezes one exact pending proposal, both sorted
pending/finalized absence slots, its governance-decision nullifier, and the
role-2 parameters plus pending-governance semantic creates before clone. Cheap
unsupported fields, signed successor epoch/phase/hash/activation/decision,
authority absence, exact hash/geometry/fact agreement, and accumulator count
`+1` precede pending-family and defensive-total caps; only proof verification,
sorted insertion, and prepared semantic mutation remain late. The shared H1
vector still applies and seals. Authority-only saturated/boundary fixtures
freeze cap-versus-late-proof, signed/semantic/counter, structural, carrier/
source-row, and rollback priorities without claiming another authenticated
success fixture. Governance approval now freezes the exact pending proposal and
slot, finalized absence/insertion slot and complete provenance record, role-2
parameters source value, governance-decision nullifier, and pending-to-approved
semantic CAS. Signed hash/successor epoch, pending presence, and finalized
absence precede pending `-1`/finalized `+1`/total caps; unsupported fields,
proposal hash/activation, later-height window, authenticated parameters/hash,
decision, semantic predecessor/successor, and count `+1` follow before clone.
Only proof verification and prepared replacement/mutation remain late. The
shared H2 vector seals the real 1-to-0/0-to-1/count-`+1` path. Authority-only
finalized saturation/boundary fixtures freeze cap-versus-late faults, carrier/
source drift, structural priority, and rollback without claiming an unreachable
second authenticated success path. Missing proposal and too-early reasons stay
exact, and authenticated parameters/proposal/pending-fact divergence remains
fail-stop;
certificate acceptance now has typed pre-clone signed envelope/proof,
reservation/key/meter negative-fact, nonce-cap, and authenticated span/counter
admission; every later execution join is now leaf-typed;
the first acceptance execution segment now separates signed certificate/units,
cryptographic proof, key-window, and authenticated reservation/key companion
failures;
the acceptance nonce join now separates signed next value, protocol advance/
slot limits, and authenticated semantic/watermark divergence;
the acceptance tuple/meter join now separates signed tuple drift, duplicate/
window/task/output/cap rejection, and authenticated meter policy/semantic
companion corruption;
the acceptance settlement/measurement join now separates signed next-state/
evidence drift, premature consumption, and authenticated funded-settlement/
reservation corruption;
the acceptance relationship/provider join now preserves exact missing-fact
rejection, separates unresolved/expired authority, and fails stop on malformed
facts or registration-history companion drift;
the acceptance lifecycle/usage tail now separates signed lifecycle drift,
authenticated counter/policy corruption, cap rejection, and checked usage/
prune arithmetic exhaustion; certificate acceptance has no unclassified leaf;
future-candidate registration now types pre-cap ID/duplicate admission and its
post-cap, pre-clone predecessor/history preparation, separates validator-rule
and PoP rejection from authenticated companion drift, and freezes the prepared
insertion position before mutation;
validator registration/rotation now types pre-clone semantic/key admission and
the history join, preserving exact active-key/missing-history reasons while
separating signed validator rules, PoP rejection, protocol references, and
authenticated companion drift; first registration additionally carries one
prepared history/create transition across clone after record caps, while
rotation carries a checked-counter/strict-PoP-prepared full-history replacement
whose two proof insertions and mutations remain late on the clone;
validator revocation/history prune now separate missing history, signed
transition/delete rules, retention/reference rejection, and authenticated
predecessor/reference corruption;
clone-before-capacity admission now proves first-registration identity and both
prune targets before changing record deltas, binds one exact active kind-9
successor to the body validator, and preserves exact replay as
`DuplicateOperation` before state-dependent checks; the cloned history-prune
candidate separately rebinds the exact revoked key/nonce/proof predecessor and
keeps signed body/delete-identity mismatch deterministic, preserving validator/
missing-fact reasons instead of capacity, subtraction, or invariant artifacts;
certificate prune now separates signed ID/delete-set drift, exact missing
certificate authority, retention/live-reference rejection, and authenticated
settlement/lifecycle companion corruption while preserving nested nullifier and
postcondition reasons; it has no unclassified leaf;
all nineteen operation families now have closed leaf reasons, capacity order,
and prepared carriers. Snapshot-closed semantic/family failures consume their
exact owner into a three-way app-private outcome: deterministic leaves are
whole-block/no-receipt invalid with explicit stable codes, typed source loss is
retryable, and authenticated/host/family invariants fail stop. Snapshot finish
still outranks the pending reason; no diagnostic string participates. Success
retains the open snapshot, decoded owner, and unsealed PoCO overlay or scheduled
lifecycle. An owner-bound single-attempt seal now additionally carries either a
PoCO plan produced from a bounded overlay clone plus canonical namespace writes,
or a rescheduled canonical validator singleton write. A private consuming
advance now folds that seal into the snapshot-owning cursor, retains the
evolving overlay/lifecycle and exact item owner, replaces the latest prefix
write, and advances only on success. It does not close the snapshot. Once the
whole body is consumed, a separate planner rebinds all cursor provenance,
merges the replayed runtime final delta with the final replace-only PoCO prefix
or the no-PoCO scheduled-cutoff refresh and the final/implicit validator
singleton, rejects raw-key/hash conflicts, and creates one sealed exact-next
JMT plan on the same snapshot. Only successful snapshot finish exposes that
inert carrier; finish failure takes precedence. A subsequent owner-only
comparator now closes body-wide receipts and mixed-body four-root comparison
inside a private classification carrier, with full provenance/final-source/
plan/static invariants before state-then-receipts mismatch classification. It
does not promote app-private `Valid`. Plan application/persistence/head update,
durable `Valid` terminal artifact/outbox, speculative-parent
and cross-epoch/handoff support, production callback durability/recovery, and
Core/ABCI host integration remain open.
Runtime resource estimation now has a separate fallible API and opaque
estimate-failure token, preserving deterministic versus typed state-read
failure without creating a receipt or mutation; operator recovery estimation
also remains independent of the on-chain fee-policy read. The legacy
infallible estimator is still the only application caller, so the new API is
not simulation, ABCI, or terminal authority. Typed historical cutoff/projection
reads, the exact estimate-input carrier, host wiring/terminal promotion,
speculative-parent storage, and ABCI integration
remain open. The existing ABCI path still erases errors
into its development-oracle behavior,
and ABCI `ProcessProposal` has no truthful `Unavailable` status. Neither
`REJECT` nor `UNKNOWN` may stand in for retry.
