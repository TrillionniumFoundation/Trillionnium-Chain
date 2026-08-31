# PoCO AI-native v1 schema boundary

Status: **draft candidate inventory; one closed, non-normative foundation/order
kernel tranche; no frozen global wire schema, implementation, activation, or
readiness claim**

Document 02 defines the draft CEV1 primitive and framing rules, but this
directory does not yet assign complete per-object wire schemas, protobuf field
numbers, storage layouts, signing roots, parser behavior, or light-client
proofs. `object-catalog-v1.toml` is a non-exhaustive planning inventory of
selected top-level admitted/proof objects; it is not the accepted-wire
allowlist, a complete schema registry, or evidence of schema completeness.
Numbered documents also define supporting records, enums, state values,
contexts, and typed IDs that are intentionally absent here. Every catalog entry remains `design-only`,
unimplemented, and inactive. Tag 50 alone now has an assigned bounded candidate
machine schema; that assignment does not turn the catalog into a complete
accepted-wire registry.

`cev1-foundation-order-kernel-v1.json` is a machine-checked candidate for the
listed CEV1 primitives, contexts, validator/parameter carriers, ordered roots,
block headers, Vote/QC, Timeout/TC, and the minimum activation/handoff anchors
required by that TC closure. It is explicitly
`candidate_non_normative` and `closed_for_listed_types_only=true`. It does not
cover proposals, DA, execution, settlement, state sync, light-client proof
verification, transport framing, or cryptographic interoperability. Its
existence therefore does not change `wire_schemas_complete=false`, the v1
normative-freeze state, or any implementation/readiness bit.

The paired corpus is also consumed by a separately authored,
standard-library-only strict decoder and semantic checker. That checker
establishes independent reproduction only for the exact listed candidate
types, encodings, digests, and rejection fixtures. It does not assign schemas
to any excluded object or verify the opaque signature carriers, so global
wire-schema, crypto-interoperability, light-client, upgrade, and freeze flags
remain false.

`v0-to-v1-activation-kernel-v1.json` adds a second bounded,
`candidate-non-normative` relation/crypto kernel. Its standalone checker
recomputes the exact listed frozen-v0 and v1 validator-set descriptor hashes,
old/new weighted thresholds, role-separated strict-Ed25519 signatures, and the
closed NoFallback epoch-boundary/empty-first-block projection. It explicitly
leaves v0 governance/finality/handoff authority, migration execution, the full
configuration mapping, complete block/light-client verification, durability,
and activation outside its proof. It therefore does not make
`upgrade_contract_complete` or any global evidence bit true.

`cev1-cross-version-activation-proof-kernel-v1.json` resolves one otherwise
ambiguous compatibility boundary without changing frozen v0. On the v0-to-v1
path, frozen `EpochHandoffProofV0` field 12 is required as exact raw CEV0
`UpgradePlanV0`; its v0-only fields 13 and 14 are forbidden and are never
reinterpreted as CEV1. A separately versioned CEV1 candidate carrier binds the
raw plan hash, one signed `V0ActivationFirst` proposal witness, and its exact
three-QC finality chain. The standalone standard-library verifier reruns and
hash-binds the existing activation kernel, exact-decodes/re-encodes field 12,
checks the field-13/14 absence rule, verifies one proposer and twelve QC
signatures, and rejects 44 exact-error mutants. This is a bounded proof
witness, not the full `OrderProposalV1` transport/admission schema; it does not
prove v0 governance-state membership, complete source authority, migration
execution, signer durability, or production activation. Therefore
`upgrade_contract_complete=false`, global wire completeness, freeze,
implementation, and activation remain false.

`cev1-order-finality-light-client-kernel-v1.json` adds a bounded third
candidate. It covers FreshGenesis and first-Ordinary targets, one exact
skipped-view TC, the scheduled EpochCheckpoint/Seal1/Seal2 chain, an exact
checkpoint attachment, one role-isolated dual-quorum epoch handoff,
V1HandoffFirst finality, and one subsequent Ordinary finality advance. Its
trust bundle is explicit external verifier input, not a consensus object. The
paired independent checker consumes raw CEV1, exact-reencodes it, recomputes
old/new epoch, set, parameter, header, checkpoint, handoff, QC, TC, and proof
IDs, and verifies 60 weighted strict-Ed25519 QC, four TC, and eight handoff
signatures. It structurally snapshots the exact imported foundation
definitions/domains/registries/constraints, enforces every decidable committed
parameter and FreshGenesis empty-payload invariant, and rejects 212 exact-error
parser/authority/crypto/chain/checkpoint/handoff mutants. This proves only one
bounded handoff path; arbitrary-length trust-path iteration, v0 activation,
state sync, and every other proof class remain excluded. Consequently
`light_client_spec_complete=false`, global wire completeness, freeze,
implementation, and activation all remain false.

`cev1-order-trust-path-iterator-v1.json` adds a separately versioned bounded
composition candidate. It accepts zero through three hops: position zero, if
present, is the exact existing FreshGenesis-only transition byte string;
later positions are exact `CheckpointAnchoredTransitionStepV1` byte strings.
The stdlib-only verifier does not import another checker or a TRNM crate. It
strict-decodes and exact-reencodes the outer path and every embedded step,
derives canonical `TrustedOrderStateV1`, consumes the prior certified-head QC,
recomputes every header/QC/checkpoint/descriptor/set/parameter/handoff/state
ID, checks independent old/new weighted quorums, and enforces strict
epoch/height monotonicity. `DigestV1` is bound to the global length-prefixed
domain formula. Every `V1HandoffFirst` header recomputes root kind 1 from the
single complete `EpochHandoffV1` sidecar wrapper, including both signature
lists, while every other ordered root remains empty. The corpus has hop
0/1/2/3 positives, replay and prefix-append determinism, 63 exact-error
mutants—including empty, wrong, and different-wrapper sidecar-root controls and
11 exact epoch-start-TC controls—and 116 OpenSSL-cross-checked signatures (88
QC, four TC, and 24 handoff). The bounded skipped-view successor carries an
exact `EpochHandoffV1` safe parent, no locked QC, and the latest finalized
checkpoint anchor. The maximum is three hops; v0 activation,
weak-subjectivity anchor selection, arbitrary-length iteration, complete
wire/crypto coverage, a second implementation, global light-client
completeness, freeze, implementation, and activation remain false.

`cev1-order-ordinary-finality-advance-v1.json` adds a bounded same-epoch
advance candidate for an already authenticated `TrustedOrderStateV1`. Its
source state is derived from the exact FreshGenesis-to-Ordinary proof with one
skipped-view TC; it then verifies two sequential three-certified-header
Ordinary advances. The first edge must consume the trusted certified-head QC.
A later edge may skip exactly one view only when a complete, weighted,
strict-Ed25519 TC authenticates the prior QC as both high justification and
lock, the latest finalized checkpoint anchor, and the immediate target view.
The stdlib-only verifier exact-reencodes all raw CEV1, recomputes every
header/block/QC/TC/state ID, checks 40 QC and eight TC signatures, and rejects
52 exact-error mutants. This is same-epoch, bounded candidate evidence only:
payload execution, arbitrary history, epoch handoff, complete wire/crypto
coverage, a second implementation, global light-client completeness, freeze,
implementation, and activation remain false.

`cev1-weak-subjectivity-checkpoint-renewal-v1.json` adds a bounded renewal
candidate on top of that exact three-hop path. It derives the prior anchor from
the checkpoint carried by hop zero and the renewed anchor from the final
checkpoint-anchored hop; neither anchor may substitute JSON summaries or the
current epoch's authority for the checkpoint epoch's context, validator-set
hash, parameters hash, application root, or state-schema root. The observed
epoch/height is the exact terminal finalized head. The verifier enforces a
positive epoch/block trusting window, strict epoch/height advancement, minimum
height advance, and same-height conflict rejection across 45 exact-error
mutants. This is deterministic checkpoint admissibility only: wall-clock
metadata, operator/governance authentication, arbitrary checkpoint selection,
unbounded history, global light-client completeness, freeze, implementation,
and activation remain false.

The frozen PoCO-BFT v0 schemas and vectors are not v1 conformance evidence. A
future v1 schema freeze must add bounded canonical encodings, domain separation,
positive and negative vectors, an independent parser, formal-model bindings,
upgrade rules, and light-client verification before any status field can be
promoted.

`cev1-transaction-batch-da-kernel-v1.json` records the first executable G2A
candidate boundary. It binds only namespace tag `0` (`TransactionBatch`) and a
local full-replication SQLite state machine: typed IDs, exact author sequence,
per-author/global capacity, durable-before-attest, sorted unique weighted
availability certificates, retrieval, repair, retention obligations, and a
durable GC tombstone. Journal schema v2 adds a checksummed attestation
high-watermark and an immutable durable-manifest checksum; it does not use
SQLite row IDs as signing sequence authority. The crate uses candidate Borsh bytes because the complete
`AgentTransactionV1`/CEV1 envelope parser is not frozen. It provides no network
service, ArtifactEvidence namespace, Order vote eligibility, Node integration,
whole-node CAS, production signing or GC authority, externally reachable byte
deletion, global wire completeness, or activation; all corresponding status
fields remain false.

`cev1-agent-market-kernel-v1.json` records the bounded executable G2B
candidate. Its explicit FreshGenesis trust bundle is only local verifier/store
input, not a consensus object. It verifies controller/session strict-Ed25519
domains, exact capability/session generations, nonzero session lanes/nonces,
one shared capability budget, exact representable operation/resource scopes,
and a monotonic per-call Order-finalized height/block CAS. Unsupported
committed/market/endpoint scopes fail closed. Its exact path is Task + funded Escrow, Bid,
one atomic requester transition that consumes the Bid, changes Task Open to
Leased, reserves Escrow, holds Bond and creates Lease Offered, then provider
acceptance to Active after resolving Lease back to Task. SQLite schema v2 has
no migration, rejects sidecars, checks durable state/journal roots on every
verified access, supports exact replay and gap-free high-watermark, and permanently fences an
ambiguous third state. This is not `AgentTransactionV1`, complete identity or
economic lifecycle, committed-set verifier, state tree, Node Order-proof
authority/integration, Verify/Challenge/Settlement,
global G2 completion, freeze, production readiness, or activation.

`cev1-verify-challenge-kernel-v1.json` records bounded executable G2C evidence
for one StakeQuorum profile: provider receipt attribution, complete inline
signed claims with unique verifier-identity weight and exact shared
statement/evidence/sequence binding, the atomic virtual BeginEvaluation +
committed decision pair, one challenge bond, evidence, provider response, and
Upheld/Rejected adjudication. Its schema-v2 journal binds a monotonic per-call
Order-finalized height/block CAS plus durable state and operation-tail roots;
the Order fact is still an unproved Node trust input. It is not all seven
verification classes, ArtifactEvidence DA,
multiple challenges, expiry/appeal, settlement, AgentTransaction wire, Node
integration, a global Compute plane, freeze, production readiness, or activation.

`cev1-object-mvcc-fee-kernel-v1.json` records bounded executable G2D evidence
for a local single-block typed-object engine. It binds explicit versioned read
and write sets, parent-snapshot speculation, canonical-index conflict retry,
complete Success/Reverted/OutOfResource receipts, four deterministic resource
classes, checked per-transaction fee deltas, and one sorted block-end credit per
destination. SQLite schema v1 atomically binds the object state, receipts,
resource totals, fee deltas and block journal under immutable existing-store
preflight. It is not global AgentTransaction wire/authorization, a real
parallel worker pool, an authenticated global state tree, the complete fee
schedule, Order/Node authority, G2 completion, freeze or production activation.

`cev1-consumption-settlement-kernel-v1.json` records bounded executable G2E
evidence for one provider/consumer, one asset, one final-valid result and one
rollup. It verifies current-height bilateral Ed25519 receipt/rollup statements,
a contiguous cumulative receipt chain, complete atomic rollup assignment, a
chain-assigned challenge-close height and a caller-amount-free one-shot
conserved settlement. Its SQLite schema-v1 journal is deterministically
replayed from fresh genesis on every verified access. Bootstrap Agent keys,
evidence certificates, result state, escrow and order finality remain local
trust inputs; cross-kernel authority, multiple assets/results/rollups,
invalid/inconclusive policies, slashing, MVCC final apply, Node integration,
global G2 completion, freeze and activation remain false.

`cev1-cross-plane-readback-kernel-v1.json` records G2F: a double-sampled,
read-only consistency join over the five local G2 stores. It binds explicit
typed lifecycle identifiers and each store identity, monotonic position,
state/metadata root, and journal tail. The DA head and selected certified batch
are read from one explicit SQLite snapshot, and every terminal receipt must
match the sampled store identity, position, Order head and state root. The
Order-proof digest remains a verifier trust input. This is not a cross-store
transaction, whole-node checkpoint, Order proof authority, Node integration,
or anti-rollback authority.

`cev1-global-execution-binding-kernel-v1.json` assigns the bounded machine
schema for registered object kind 50. It fixes the exact CEV1 body/object/state
and application envelope, all five digest domains, typed state key, leaf and
256-level leaf-to-root sparse path, the single-witness candidate claim, and
the inert later-height create material. Its independent stdlib checker exact
decodes/re-encodes the raw claim and both nested values, reproduces all hashes,
and exercises 51 exact-error negative controls. The fixture supplies an
already-authenticated strict-ancestor fact; it does not verify the external
Order proof. Even its exact membership positive terminates at
the positive carrier: the authoritative local Order-state writer consumes a
linear terminal owner, commits tag 50, freshly reconstructs its receipt, and a
typed receipt projection joins it to separately verified later Order finality.
The public raw claim is not self-authorizing, and this checker does not verify
the external Order proof. `ExecutionBindingWriterUnavailable` remains a
reserved compatibility error code, not the legal writer-path terminal. This
listed-type schema therefore leaves global wire/schema and vector completeness,
normative freeze, G2, Node integration, production, and activation false.
