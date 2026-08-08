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

Separately from application-store schema v5, Core `SafetyState` schema v5
introduced a canonically ordered `DurablePayloadValidationObligationV0` before
either `ValidatePayload` or `ValidateSyncedPayload` may escape a
`PersistSafetyState -> StorageAck` barrier. Each record binds the Core-selected
route, full `ValidationId`, exact `SignedProposalV0`, exact
`PayloadValidationParentV0`, and `first_recorded_revision`; the live invariant
also binds the generation to that first revision. `StorageAck` reconstructs a
request only from the durable record and its matching volatile proposal mirror.
Core `SafetyState` schema v6 adds a separate canonically sorted
`DurablePayloadValidationCompletionV0` set keyed by `(route, full
ValidationId)`. Every direct or synced callback atomically replaces its exact
obligation with a same-key completion before persistence. The completion
stores all three result variants, the complete `ValidatedBlockCommitmentsV0`
for `Valid`, and `first_recorded_revision`; an exact same-result callback is
therefore durably idempotent after restart. Reuse under the opposite route,
different source/owner facts, a different result, or different `Valid`
commitments is invariant or a typed integration conflict and cannot overwrite
the record. `Unavailable` closes only that generation, permitting a later
generation for the same block. These tombstones are distinct from block-ID-
level terminal payload facts, which continue to encode only cross-generation
`Valid`/`DeterministicallyInvalid` semantics. Exact synced cancellation removes
its obligation behind the persistence barrier without fabricating a callback
completion. Safety halt clears obligations in the same revision and retains
prior completions. Completion eviction is disabled; registration reserves its
future slot under `completions + obligations <= max_observed_messages`.

Core bounds the complete signed-proposal durable resource -- logical block plus
exact certified-tail witness -- by authenticated
`max_consensus_message_bytes`. Its aggregate obligation budget additionally
counts the fixed route/ID/revision/parent facts and any exact parent header.
Recovery validates every schema-v6 obligation and completion and then rejects
a non-empty obligation set with `InvalidRecovery`; it does not reissue pending
validation. Safety-state
schema v5 has no implicit migration. Completion-only recovery provides durable
exact-result suppression, but non-empty obligations remain fail-closed. This
is durable pre-effect capture, cleanup ordering, and result idempotence, not
crash replay, callback exactly-once, type-level callback authority, or recovery
liveness.

After that wrapper/route check and process-local claim, and before any host or
snapshot read, application-store schema v5 durably reserves
`(route, full ValidationId)` in the same SQLite database. One
`BEGIN IMMEDIATE` transaction performs the unique insert or reads the existing
row. A versioned, domain-separated fingerprint binds the route and complete ID
to the exact raw target header, application payload, ordered evidence, and
parent source. Only an exact match coalesces/suppresses a duplicate across
independently materialized request graphs or processes; a route, raw-source,
target, or parent splice under the same full ID is an invariant. The table has
a hard 65,536-row ceiling with no eviction, while exact duplicates still
coalesce at capacity. State-sync snapshot generation scrubs all reservation
rows transactionally from the temporary copy and verifies that copy is empty,
without changing the source database. This is a durable reservation and
cross-instance congruence boundary, not an evaluated result, takeover lease,
callback outbox, or process-wide callback exactly-once guarantee.

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
cursor can perform real runtime attempts and success-only advance. Before
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
cannot form an input. This is type-level callback material only: it does not
call `Core::step`, persist or deliver an outbox, or provide
`AuthorizedNativeCheckpointExecutionV0`, checkpoint, or ABCI authority. The
pre-terminal failure carriers share that private,
non-cloneable, non-serializable, no-parts/no-standalone-cause boundary. Plan
application/persistence and head update, non-runtime family semantic
decode/execution/cursor advance,
speculative-parent overlays, host callback-outbox persistence/delivery, actual
Core callback execution, ABCI wiring, and cross-process rollback
protection remain hard open prerequisites before any terminal/Core callback
path. The object-graph gate performs no terminal mapping, and only the current
private admission branch is proven not to emit a callback for a losing clone.
The private route-bearing bridge now proves that `Proposal` maps only to
`PayloadValidated` and `Synced` only to `SyncedPayloadValidated`, but it does
not submit that input to a Core instance or establish callback delivery.
The reservation stores no evaluated artifact, result, JMT plan, or outbox. A
future validation-time atomic boundary must persist a versioned revalidatable
artifact together with callback-outbox intent; a distinct Finalize-time atomic
boundary must revalidate the exact authority and couple JMT/domain apply,
root/native-head persistence, head advancement, and applied state. Neither
boundary, authenticated replay tickets, completion retirement after durable
host-delivery acknowledgement, speculative-parent/BlockTree reconstruction,
application-reservation takeover, evaluated-artifact persistence, host
callback-outbox scheduling/delivery acknowledgement, crash takeover, Core
callback delivery,
nor callback exactly-once is implemented. Core's completed `StorageAck`
cleanup barrier and completion tombstone are not a host callback-outbox
delivery acknowledgement.
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
failure. A further consuming attempt now constructs PoCO authority state only
from the pinned authenticated projection and schedules validator transitions
only against the retained authenticated lifecycle; it accepts no supplied
projection/lifecycle loader and rebinds decoded PoCO values to their exact raw
bytes. Semantic/family failures explicitly finish the owned snapshot before
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
consumer-key prune uses that negative-fact reason before clone, keeps signed
delete/retention/reference rejection deterministic, and keeps authenticated
retention arithmetic, certificate decoding, and nonce-watermark faults
invariant;
meter definition preserves nested typed errors and separates deterministic
signed policy/semantic shape from deterministic active-parameter cap rejection,
while meter prune rejects a missing authority policy as a pre-clone negative fact;
meter retirement distinguishes signed ID/height/next-state rejection, missing or
already-retired authority, and authenticated old-fact/authority divergence;
meter prune validates signed IDs before policy lookup, separates nullifier and
active/retention/reference rejection, and fails stop on authenticated retention
arithmetic or certificate decoding;
fund settlement maps its remaining signed certificate/commitment/units and
semantic-shape failures deterministically while preserving nested typed
nullifier/counter/CAS reasons;
release settlement validates signed ID and reservation existence before clone,
then separates signed delete shape from authenticated leaf/reservation drift;
unrefined leaf failures conservatively remain authenticated-overlay invariants
without string matching. Success retains the open snapshot, decoded owner, and unsealed PoCO
overlay or scheduled lifecycle. PoCO leaf-reason refinement, write sealing,
multi-operation cursor integration, success-only cursor advance, receipts, and
terminal failure promotion remain open.
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
