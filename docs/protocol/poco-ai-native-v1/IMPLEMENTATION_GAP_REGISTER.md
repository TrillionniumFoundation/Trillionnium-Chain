# PoCO AI-native Stack v1 implementation gap register

Status: **active design-gap register; v1 is not implemented, not activated, and not release-ready**

This register tracks the distance between the draft v1 target and the current
PoCO-BFT v0 implementation baseline. It is not a readiness checklist that can
be satisfied by prose alone.

## 1. Current machine truth

```text
architecture_status=adopted
specification_status=draft
normative_freeze=false
current_implementation_baseline=poco-bft-v0
implementation_status=not-implemented
node_support=false
protocol_activation=false
production_candidate=false
release_ready=false
new_bft_safety_theorem=false
```

The authoritative typed status is [`status.toml`](status.toml). If prose and
that file disagree, freeze is blocked; no “implementation wins” rule applies.

## 2. Reusable v0 safety assets

The following are useful evidence/design inputs, not v1 implementation:

- deterministic no-I/O Core/effect boundary;
- weighted quorum, safe vote/lock, restricted TC, three-chain finality;
- canonical bounded encoding discipline and domain separation;
- persist-before-sign SafetyStore, SignIntent, signer journal, external
  watermark, fail-closed recovery, and whole-node checkpoint design slices;
- application overlays, authenticated roots, ordered-finalization model, and
  bounded formal mutants;
- epoch checkpoint and dual-quorum handoff concepts.

V0 proposal bytes, full-payload rule, root kinds, receipts, vectors, formal
models, and light-client rules remain v0. They cannot be relabelled as v1.

## 3. Blocking gaps by plane

### Agent — design only; bounded candidate kernel present

- draft logical schemas now define `AgentTransactionV1`, AgentID, capability,
  session key, budgets and nonce lanes, but no frozen machine wire schema,
  parser, canonical vectors, or implementation exists;
- no implementation of revocation generation, scoped budget/rate enforcement,
  or nonce lanes;
- no shared-budget concurrency proof, storage migration, wallet, RPC, or SDK.
- one candidate-only local kernel now executes root capability/session grants,
  explicit session lanes, exact nonce/generation checks and a shared budget;
  it is not the frozen global wire/parser, identity/key lifecycle, delegation,
  revocation, wallet, RPC, SDK, state tree, Node or production authority.

### Market/Task — design only; bounded candidate kernel present

- draft logical schemas and closed transitions now cover offer/lease/escrow/
  checkpoint/migration, but they are not frozen, formally proved, or implemented;
- no deterministic lifecycle, SLA/deadline/refund implementation;
- no resume/migration/cancel/timeout crash recovery or conservation evidence;
- current legacy task path is linear and is not v1 authority.
- one candidate-only SQLite kernel now executes only `Task + funded Escrow`,
  Bid, atomic five-object Lease Offered, and provider acceptance to Active;
  start/result/settlement/cancel/timeout/migration/checkpoint/refund and all
  production integration remain absent.

### Compute/Verify — design only

- draft `VerificationProfile`, receipt outcome/status, statement binding,
  result/challenge transitions and proof carriers exist, but no frozen registry,
  machine schema, verifier interface, vector, or implementation exists;
- ZK/TEE/re-execute/stake/optimistic/subjective methods are design categories,
  not implemented consensus profiles;
- no evidence-retention, evaluator independence, privacy, or correlated-slash
  contract.

### Data Availability — design only

- draft committee/policy, batch/chunk/certificate, signed retrieval/repair,
  retention and obligation schemas exist; none has a runtime implementation;
- no durable-before-attest journal/signing service or whole-node binding;
- no availability certificate parser, quota/backpressure, retention/GC holds,
  withholding adjudication, state-sync, or light-client implementation;
- no erasure coding or DAS is claimed or currently required.

### Coordination/Order/Settlement — design only

- the node has no production Vote loop/effect driver/authenticated P2P/state
  sync; its default/all-features closure, the complete active workspace graph,
  and lockfile no longer reach the legacy application crate or Tendermint;
  historical source remains outside the build graph for audit;
- a non-normative, closed-for-listed-types CEV1 foundation/order-kernel
  candidate now covers contexts, validators/parameters, typed IDs, ordered
  roots, header, Vote/QC, Timeout/TC, and minimum activation/handoff anchors,
  with checked positive/negative vectors; the separate bounded strict-Ed25519
  corpus covers only listed Order signature claims. Neither tranche is a
  complete machine wire schema, signer implementation, global crypto-interop
  corpus, or freeze;
- execution remains serial/single-nonce with a global fee-collector hotspot;
- no deterministic object MVCC, AgentBatch, fee-delta aggregation,
  ConsumptionRollup, dual-finality, or v1 settlement implementation;
- one bounded v0-to-v1 activation relation/crypto verifier exists; a cumulative
  cross-version proof kernel now exact-decodes raw CEV0 `UpgradePlanV0` field
  12, forbids frozen-v0 fields 13/14 on this route, and verifies a separate
  signed CEV1 first-proposal/three-chain carrier. Complete frozen-v0
  governance-state membership/finality/handoff authority, full
  `OrderProposalV1`, migration execution, activation, and no-fallback recovery
  campaigns remain absent.

## 4. Cross-cutting evidence gaps

- normative wire schemas and closed enums: incomplete; one non-normative
  foundation/order-kernel candidate is machine-checked;
- canonical positive/negative/conformance vectors: incomplete; the same
  candidate has 27 positive, one ordered-root derivation, and 24 negative
  cases but no global corpus;
- v1 formal models and retained mutants: incomplete; three bounded candidate
  kernels cover weighted-order quorum/finality, timeout lock discipline, and
  epoch handoff/activation, with 15 bounded invariants, three reachable legal
  witnesses, and seven retained mutants that must produce counterexamples;
  this is not a complete protocol model or proof;
- independent parser/light client: one separately authored standard-library
  parser now checks the exact foundation/order closed corpus, all 24 negative
  fixtures, and checker-owned malformed-input mutants; a separate bounded
  strict-Ed25519 checker covers four validators, one Vote statement, two
  distinct Timeout statements, four QC signatures, four complete per-entry TC
  statements/signatures, weighted quorum, and 18 negative cases. A separate
  activation-kernel checker has one positive and 31 negative cases and
  independently recomputes the exact listed frozen-v0 and v1 validator-set
  descriptor hashes, both weighted quorums, strict role signatures,
  NoFallback, and the first empty v1 activation projection. The global
  parser/crypto corpus, complete QC/TC transition semantics, full v0 authority
  verification, migration execution, and complete upgrade contract remain
  absent. A cumulative cross-version activation-proof checker has one positive
  and 44 exact-error negatives, consumes exact raw CEV0 field 12, requires
  frozen fields 13/14 absent, verifies one CEV1 proposal-carrier signature and
  twelve three-chain QC signatures, and cross-checks all 13 valid signatures
  with OpenSSL. It still does not prove field-12 governance membership,
  complete source authority, migration execution, the full proposal contract,
  durability, or freeze. A separate independent `OrderFinalityProofV1`
  checker now consumes
  raw CEV1, exact-reencodes all five top-level inputs, verifies 60
  strict-Ed25519 QC, four timeout, and eight role-specific handoff signatures,
  and independently recomputes checkpoint/attachment, old/new descriptor/set/
  parameter authority, dual weighted quorums, V1HandoffFirst finality, and one
  subsequent Ordinary finality advance. It exact-compares its imported
  foundation type/domain/registry/constraint snapshot, checks all decidable
  committed parameter and FreshGenesis empty-payload invariants, and rejects
  212 exact-error mutants. A bounded iterator now composes that authority into
  exact 0/1/2/3-hop paths: step zero remains the existing FreshGenesis-only
  raw carrier, later steps use a versioned checkpoint-anchored carrier, all
  intermediate state/QC/descriptor/set/parameter/handoff bindings are
  recomputed, the global length-prefixed `DigestV1` rule and the complete
  `V1HandoffFirst` sidecar root are bound, and one exact epoch-start
  skipped-view TC proves the identical handoff safe parent, absent lock, latest
  finalized checkpoint, and immediate target. 63 exact-error mutants are
  retained, and OpenSSL cross-checks all 116 three-hop QC/TC/handoff signatures. V0
  activation, operator-authenticated/general weak-subjectivity anchor
  selection, arbitrary-length iteration, multiple skipped
  views or general pacemaker histories, other proof classes, and a complete light client
  remain absent;
- bounded weak-subjectivity renewal: a separate raw-CEV1 candidate now derives
  the prior and renewed anchors from the first and latest checkpoints on the
  exact verified three-hop path, binds checkpoint epoch/context/validator set/
  parameters/application and schema roots, enforces positive epoch/block age
  windows plus strict monotonicity, and rejects 45 exact-error mutants including
  same-height conflict. It does not authenticate the operator/governance trust
  decision, accept an arbitrary checkpoint, evaluate wall-clock evidence,
  remove the three-hop bound, or complete the global light client;
- second implementation/interoperability: absent;
- multi-store/DA crash and hardware durability evidence: absent;
- authenticated multi-node WAN/Byzantine/epoch/state-sync evidence: absent;
- committed-goodput/tail-latency/unit-cost evidence: absent;
- economics, related-party/Sybil/meter/privacy/slash policy review: absent;
- external consensus/cryptography/security review: absent;
- reproducible v1 node/release/SBOM/provenance/runbooks: absent.

## 5. Delivery gates

### G0 — sovereign native baseline

G0's active dependency graph is closed: the legacy application and node are
excluded from the workspace, the PoCO optional legacy edge is gone,
`Cargo.lock` contains no Comet/Tendermint/ABCI package, and executable adapter
and shipped configuration markers carry no old endpoint/binary authority.
Historical source remains outside the build graph for audit. Reconcile the
dirty tranche into a reproducible reviewed baseline; production and release
flags remain false because a real native engine and later gates are incomplete.

### G1 — minimal frozen-v0 vertical safety path

The native schema-v3 validation journal can now issue a non-cloneable,
owner-affined checkpoint-facts capability from terminal K only after a fresh
full-store audit, and freshly reconfirm the exact global sequence, row
checksum, execution artifact, Core-D digest, and retained request-bound
C-shaped provenance. In addition, the strict authority route derives the
NativeValid transition from opaque D, fresh-confirms the exact live
SafetyStore head and pending Vote intent, and closes K. The default Node now
also joins that terminal K with fresh Safety facts and an already-exact
operational signer head, advances one independent checksum-linked whole-node
CAS successor, and resolves an applied-but-lost CAS response only by fresh
exact target readback. Only that confirmed successor permits Core
`StorageAck`; its sole `RequestSignature` remains private and inert. This is
still not restart/process takeover or signing authority.

The active `trnm-native-execution-v0` package now closes the complete
ordinary-body deterministic transition and local durable-P boundary. An
independent immutable preview derives the four roots, receipts, and request/
write-plan fingerprints without accepting a BlockId, expected roots,
persistence, or authority. Final execution accepts an exact authenticated
committed or prepared parent snapshot supplying parameters, signer/replay policy,
validator lifecycle, PoCO state, and runtime objects; the engine applies
runtime, lifecycle, PoCO/cutoff, and system writes in one collision-checked JMT
plan; and SQLite atomically retains canonical P plus the complete target
snapshot/overlay. Prepared P rows form a BlockId-keyed forkable overlay DAG;
sibling forks and multi-level descendants survive reopen under unique monotonic
sequences and stable pre-commit application commit IDs. Explicit finalization-
side commit accepts only the current committed head's exact child, retains its
descendants, and atomically prunes losing siblings. QC is never interpreted as
application finality. Fresh immutable reopen independently recomputes roots and
audits the committed prefix plus complete prepared DAG; metadata-only or P-only
partial commits are permanently fenced. A private default-Node boundary can
fresh-confirm P, consume the issuing Core's application seal, and pass only
Core's opaque accepted-D carrier to the native validation journal. The current
legacy-genesis fixture lacks authenticated finalized-parent authority, so this
is not yet a positive process path. A separate strict package integration and
the private default-Node method now close opaque Core-D -> exact real
Safety-C -> terminal K. A bounded strict integration continues through the
successor-only whole-node CAS and one inert `RequestSignature`; it does not
turn the legacy-genesis fixture into finalized-parent process evidence.
SIGKILL/restart takeover, signer-journal submission, signing, and broadcast
authority remain absent.

Complete the finalized-parent process host, Vote/Timeout SafetyRules,
reconstruction of the linear P/D/C/K/checkpoint carriers, finalization, and the
full crash matrix. Do not add v1 semantics to v0.

### G1.5 — v1 normative freeze and baseline measurement

Complete 01–10, machine schemas, vectors, formal models, independent parser,
light-client and upgrade contracts; run only enough 4/7-node v0 measurement to
establish the comparable baseline. A written draft is not freeze.

The bounded same-epoch Ordinary continuation candidate now derives its source
state from authenticated FreshGenesis/Ordinary raw CEV1 and verifies two
sequential three-certified-header advances. It consumes the prior certified
head QC, permits at most one complete checkpoint-anchored skipped-view TC per
advance, passes four positive controls, 52 exact-error negatives, and 48
OpenSSL QC/TC checks. Payload execution, arbitrary history and epochs,
complete wire/crypto coverage, second-implementation interoperability, global
light-client completion, and normative freeze remain open.

### G2 — v1 vertical implementation

Implement Certified DA, Agent/capability/task objects, exact verification
profiles, deterministic MVCC, nonce lanes, AgentBatch, multi-resource fees,
ConsumptionRollup, dual finality, native state sync, and v0-to-v1 activation.

The first G2A executable tranche is now present as a candidate-only local
`TransactionBatch` kernel. It closes deterministic typed objects, local SQLite
durable-before-attest, bounded author/global queues, strict weighted
certificate admission, retrieval/repair, retention, GC tombstones, and signed
attestor-equivocation evidence under tests. Its schema-v2 journal uses a
checksummed high-watermark and immutable durable manifest; production GC byte
deletion remains unreachable because no finality/CAS permit issuer exists. It
does **not** close G2 or G2A:
ArtifactEvidence, transaction-envelope interoperability, dissemination,
remote retrieval/repair, whole-node checkpoint/CAS, Order integration, Node
reachability, production signing/GC authority, and multi-host fault evidence are
still absent.

The local DA crate now also contains a candidate-only signed full-range
retrieval proof and exact-repair adapter. It authenticates a pinned requester,
committee responder, exact certificate/window, every canonical chunk-inclusion
path, reconstructed batch, and target scope/store/config/certificate before
consuming a linear repair carrier. It does not provide a network protocol,
generic range service, requester registry, durable responder signer journal,
withholding/non-response authority, ArtifactEvidence, whole-node CAS, or Node
reachability; therefore DA-plane and global G2 truth remain false.

The first G2B executable tranche is also present as a candidate-only local
Agent/Market kernel. It closes strict controller/session Ed25519 domains,
capability generation, explicit nonce lanes with one shared budget, and exact
Task/model/tool/profile/privacy/resource scope checks. `CommittedSet` and
market/endpoint scopes fail closed while their verifier/carrier is absent;
provider acceptance resolves `Lease -> Task` before task-scope admission. A
separate per-call Order-finalized context advances height/block identity under
durable monotonic CAS, so deadlines and rate windows are no longer frozen in
genesis. SQLite schema v3 checks durable state, journal and finalized-block
roots on every
verified open/read/write, in addition to atomic task/funded-escrow creation,
one-shot bid consumption, escrow/bond reservation, Lease Offered-to-Active,
exact replay and crash/tamper tests. It does **not** close G2 or G2B: the Order
context still lacks Node proof authority, bootstrap IDs are not the complete
identity/key lifecycle authority, `CommittedSet` remains unavailable, and
global `AgentTransactionV1`, the full task lifecycle, state tree/MVCC/fees,
whole-node CAS, Verify/Challenge/Settlement, interoperability and production
authority remain absent.

The first G2C executable tranche is present as a candidate-only local
Verify/Challenge kernel for the `StakeQuorum` class. Provider receipts,
strictly unique verifier-identity weight, exact shared claim
statement/evidence/sequence binding, atomic evaluation history, one challenge
bond, evidence, response and Upheld/Rejected adjudication are durable under
tests. Duplicate trust keys, non-four-member verifier sets, arithmetic overflow,
over-64-entry evidence, and inconsistent verifier-set/profile commitments fail
closed. A per-call Order-finalized height/block fact advances under durable
monotonic CAS, and SQLite schema v3 immutable-read-only preflights existing
stores and checks both state and operation-tail roots on every verified access.
It does **not** close G2C or G2: the Order fact
has no Node proof authority, ArtifactEvidence DA remains unverified, the other
six verification classes, expiry/withdraw/appeal, concurrent challenges,
Agent/Market and Settlement integration, whole-store anti-rollback authority,
global wire/interoperability and production authority remain absent.

The first G2D executable tranche is present as a candidate-only local
single-block object-MVCC and fee-delta kernel. It binds typed-object versions,
explicit read/write sets, parent-snapshot speculation, canonical-index conflict
retry, all three receipt outcomes, four resource classes, checked pricing and
conserved per-transaction fee deltas. Fee destinations are credited once per
block in sorted order rather than written by every transaction. SQLite schema
v1 atomically binds objects, receipts, resource totals, fee deltas and journal
roots and rejects sidecars/schema/root tamper under immutable existing-store
preflight plus deterministic full-journal replay. It does **not** close G2D or
G2: global AgentTransaction authority,
real worker parallelism, create/delete and full operation semantics,
authenticated JMT/global state proof, all resource classes, Order/Node proof
authority, cross-plane stores, Settlement and production authority remain
absent.

The first G2E executable tranche is present as a candidate-only local
single-asset ConsumptionReceipt/ConsumptionRollup/Settlement kernel. It binds
current-height bilateral signatures, a monotonic and period-contiguous receipt
chain, exact cumulative usage and charge, complete receipt assignment into one
rollup, a chain-assigned challenge-close height and a one-shot settlement whose
amounts are derived from committed state/policy and conserve the complete
escrow. SQLite schema v2 uses immutable read-only preflight, state/journal and finalized-block roots
and full deterministic journal replay. It does **not** close G2E, integrated
private alpha or G2: Agent identity/key state, ArtifactEvidence DA,
Result/Challenge state and Order finality are local verifier inputs; multiple
assets/results/rollups, invalid/inconclusive/slash policy, MVCC final apply,
Node integration, whole-store rollback authority, state sync and production
authority remain absent.

G2F now adds a candidate-only five-store fresh-readback join. It double-samples
DA, Agent/Market, Verify/Challenge, MVCC/Fee, and Consumption/Settlement after
each store's own authenticated reopen and rejects any intervening sequence,
identity, state-root, journal-tail, Order-head, context, or typed lifecycle-ID
change. The DA head and selected certificate share one SQLite snapshot, while
every terminal receipt is matched to the sampled store identity, position,
Order head and state root. This proves only a stable local co-observation; the
Order-proof digest remains a trust input. Cross-store atomic commit, whole-node
CAS, anti-rollback authority, Order-proof authority, Node process integration,
and global G2 completion remain absent.

A follow-on Node-private candidate now narrows two of those gaps without
promoting G2. A new zero-Node-dependency Rust verifier consumes the exact raw
CEV1 FreshGenesis trust bundle and direct three-certified-header proof,
requires an independently pinned trust-byte digest, recomputes all committed
IDs and weighted QC authority, and verifies every signature with strict
Ed25519. The private Node admission then consumes one already-confirmed G2F
carrier, performs a second five-store fresh rejoin, requires the projection to
remain byte-exact, and advances a separate SQLite checkpoint by exactly one
predecessor-bound CAS with mandatory fresh source/target readback. Exact target
readback resolves an applied-but-ack-lost result; exact source and every third
state remain non-authoritative.

A separate non-Node global pre-vote candidate now closes one bounded execution
path without promoting G2. It freshly authenticates one certified local DA
batch, retrieves the complete byte range, strictly decodes exactly one bounded
candidate item, and runs the real Agent/Market, Verify/Challenge, MVCC/Fee and
Consumption/Settlement preview reducers from one exact five-store parent cut.
The four preview roots and receipts, certified DA obligation, retrieved bytes,
and source-cut digest form a domain-separated **candidate composite root**.
Only an exact root match plus unchanged DA/five-store readback can advance the
independent validation sequence by successor-only SQLite CAS and mint the
private, non-cloneable pre-vote carrier. Reopen checks reauthenticate the exact
prepared row, generation and checkpoint checksum. Missing or partial DA,
non-canonical/multiple items, invalid signature/nonce/version/fee/conservation,
root mismatch, stale CAS and source drift all fail closed under executable
controls.

The same candidate now also closes one strictly local terminal-facts CAS. A
private non-cloneable owner issued only by the exact verified-finality source
apply path binds the prepared generation/checksum, candidate composite tip,
five plane terminal receipt/root commitments and candidate-local final
execution root. One SQLite
transaction inserts the history successor and finalized evidence row while
CAS-advancing metadata; exact retry, acknowledgement loss, reopen,
stale/fork/root substitution, partial/torn rows and logical metadata rollback
are covered. Verified Order finality for the exact prepared candidate now
drives recoverable application through all five source planes, backed by
checksummed direct-successor finalized-block journals, and issues the linear
terminal owner only after fresh terminal readback. This supports
`whole_node_finalization_cas=true`,
`normal_build_finalization_owner_issuer=true`, and
`source_plane_finalization_apply=true`; it does not mint Node authority or
prevent rollback of a complete database file.

T0-C/T0-D add a distinct manifest-bound Node-private boundary without
promoting that older runtime. One exact non-Clone
`G2CandidateLocalFinalizeJoinV2` is the sole owner-bearing ingress. Its complete
request, eight roots, plane roots, receipt inventory, preview digest and join
digest are canonically projected into a two-record anchor/successor SQLite
journal. Receipt count is rejected before nested serialization; allocation-free
Borsh length counting and a hard-limited writer keep the complete snapshot
inside the fixed record budget. The target can advance only by exact metadata
CAS, and every reported result is resolved by immutable fresh history readback.
Reopen accepts caller-supplied external trusted-pin data, including its one
legal direct successor for applied-but-response-lost recovery, but remains
data-only. A newly produced exact typed join must reproduce the durable
snapshot byte-for-byte before the owner can exist again.

T0-E foundation now closes two narrower in-process prerequisites without
claiming Node reachability. The canonical Order-state store can seal the real
manifest-bound G2 application block only from its non-forgeable recovered
parent owner, with complete fresh store/head/pin audits before and after and an
explicit unique-direct-successor check; its inner application parent is never
exposed. The T0-D Node owner now retains the live SQLite journal and offers one
crate-private double-fresh exact revalidation against its retained typed join
and target pin. No journal, decoded record, raw snapshot, or exact join escapes
from that owner.

A smallest normal-build T0-E process tranche is now source-wired behind two
explicit candidate-only `trnm-poco-node` commands. Five new `open_existing`
entry points reject missing, symlink and non-regular source stores without
creating or migrating SQLite state. `prepare-g2-manifest-bound-candidate-v2`
can create only the private T0-D anchor, stable lifetime-lock record and an
independent process-pin anchor after exercising the complete existing-source
issuer; that process-pin anchor seals the resulting exact-join commitment.
Prepare retries acquire the same exact lock, rerun that issuer, and accept only
the durable prefix `none -> lock -> T0-D anchor -> process-pin anchor`; exact
prefixes resume idempotently while reordered, mutated, temporary, or targeted
states fail closed.
`run-g2-manifest-bound-candidate-v2` requires externally retained
manifest and process-pin SHA-256 values, holds the exclusive OS lock, rebuilds
the five-source input/preview, seals from the recovered canonical Order parent,
exact-joins the request, rejects any difference from the prepared commitment
before consuming that join at T0-D, and CAS-advances the separate process pin.
An externally retained old anchor can recover only its one schema-bound,
byte-exact anchor-to-target successor after the T0-D journal and full issuer
have been replayed. An exact durable temporary target completes the rename; an
exact duplicate beside an already-current target is removed durably; every
foreign or malformed temporary state fails closed. The target schema binds the
T0-D journal ID, process scope, generation-one successor, checksum and process
predecessor, as well as the direct canonical candidate height. `READY` is
emitted only after the same issuer is rerun and the source identities,
canonical pin, T0-D owner and process pin are freshly revalidated; the owner is
then retained until control-stdin EOF performs a final revalidation and clean
shutdown. A normal-build integration target and private unit-test matrix now
cover fail-closed CLI paths and the recovery/schema primitives in source. A
feature-gated test-support builder now reuses the real DA certification rig to
create all five real source SQLite stores, a parent-aligned canonical Order
store, private T0-D namespace, and exact Borsh manifest. It exposes only paths
and hashes to the integration test; it cannot create or pass a typed join,
owner, or authority root to the normal CLI. The feature integration target now
passes 7/7 tests and spawns only the normal `trnm-poco-node` binary. It observes
an idempotent byte-stable PREPARED retry, P1 READY, duplicate lock rejection
before READY, P1 SIGKILL (signal 9), a different-PID P2 using the saved old
anchor to recover the identical unique target and reach READY, and stdin-EOF
clean exit. Five dynamic negative classes—DA mode drift, canonical Order mode
drift, malformed temporary target, process-pin rollback after an externally
observed target, and T0-D journal rollback—fail before READY. The full feature
suite (74 unit, 7 process and 7 doc tests), strict all-target Clippy, the global
boundary, and project preflight (`errors=0`) also pass. This moves only the
candidate-local process-integration, external-pin process-persistence and
external-pin-authenticated process-owner facts; whole-Node and G2 fields do not
move.

The current path-level hash/stat checks around separate immutable and rusqlite
connections narrow accidental replacement exposure; they do **not**
descriptor-bind SQLite through `openat`/a retained directory descriptor, close
a malicious same-UID rename race, or pin the namespace inode and effective-UID
owner for the process lifetime. The candidate process pin is only as
authoritative as the operator-retained checksum supplied at restart; it is not
an authenticated production anti-rollback root. Thus the now-observed
database-only rollback rejection must not be read as coherent pin-plus-database
rollback protection. The journal
cannot recreate the join, and there is no source apply, vote, signer, Core,
network, whole-node checkpoint, or anti-whole-store rollback authority.

This candidate item is not the frozen `AgentTransactionV1` wire, and its
candidate composite root is not the normative application JMT root. The
bounded local path now does establish one exact Order-state membership binding,
but there is still no multi-level speculative overlay, production Node/process
owner, state sync, settlement acknowledgement, signing, or broadcast path.
Therefore
`candidate_runtime_implemented=true` and
`order_state_membership_binding=true` remain intentionally compatible with
the manifest-bound candidate-local tranche's `node_process_integration=true`,
the aggregate/global `node_process_integration=false`, and
`g2_global_complete=false`.

The authority-refinement path is now continuous and linear. The independent
Order-state crate consumes an existing non-Clone
`WholeNodeFinalizationOwnerV1` into an exact-parent, create-once permit, proves
the derived tag-50 key absent, commits the immutable version-zero value, and
freshly rebuilds the successor height/root/value/256-sibling receipt. A typed
receipt projection can mint `VerifiedOrderStateExecutionBindingV1` only when a
separately verified later Order-finality carrier names that exact height and
post-state root and proves the encoded candidate as a strict certified
ancestor. The global seam then rechecks context, candidate height/block,
composite root, and final execution root against the retained terminal owner
before returning the same owner. Public terminal commitments, raw claims,
cloneable create material, bare roots, and fabricated receipt projections are
data rather than authority. The global crate itself still has
`order_binding_positive_carrier_issuer=false`; the normal issuer lives in the
independent Order-state/verifier path.

The tag-50 listed-type machine schema and corpus are independently reproduced
without importing a TRNM crate. Six positive controls cover the canonical
body/object/state, envelope/key/leaf, 256-level sparse membership, claim, and
positive carrier terminal; 51 exact-error mutants cover the bounded parser and
every nested identity/context/version/path boundary. The corpus supplies an
externally authenticated strict-ancestor fact and does not itself verify the
external Order proof. `ExecutionBindingWriterUnavailable` remains a reserved
compatibility error code, not the legal writer-path terminal. This closes the
local machine schema, authoritative tag-50 writer, typed receipt projection,
and membership binding; it does not close global schema/vector completeness,
G2, freeze, production, or activation.

This is still a bounded FreshGenesis/single-epoch/consecutive-view candidate.
The independent Rust verifier strictly decodes the candidate claim, binds the
exact verified Order context/finalized header and candidate/final roots, and
cryptographically verifies the exact tag-50 256-level sparse-tree membership
path beneath the finalized `post_state_root`. A bare height comparison cannot
supply ancestry: the candidate must be present in the verifier's private
certified prefix. Separately, the older G2F checkpoint continues to record the
verified Order proof and stable five-store projection as parallel local
co-observations; it does not prove that projection beneath the Order state
root, so `order_finalized_cross_plane_authority=false` remains exact. Existing
checkpoint files are admitted only after immutable read-only schema/metadata
preflight, sidecar rejection, and exact file-identity revalidation before any
mutable PRAGMA or transaction.
The checkpoint database does not atomically lock or commit the five source
stores, does not establish anti-whole-store rollback authority, is not wired
to the Node process, and cannot acknowledge Core, settle, sign, or broadcast.
TC/handoff trust progression beyond this direct bounded path, the global light
client, whole-node authority and global G2 completion remain absent.

### G3 — evidence-driven Order decision

Run controlled 7/31/100-validator WAN/fault/performance matrices. Retain the
weighted chained-HotStuff kernel unless measured latency, async/DDoS liveness,
censorship, tail-fork/MEV, or scale evidence crosses a predeclared requirement.

### G4 — adversarial/public candidate

Close remote signer/HSM, multi-region soak, rollback drills, independent
implementations, external review, reproducible artifacts, SBOM/provenance,
operators, dashboards, alerts, incident replay, and economic shadow campaigns.

## 6. Truth promotion rules

Each status promotion requires the corresponding artifacts and CI checks in
one reproducible commit. `draft -> frozen`, `not-implemented -> implemented`,
`node_support=false -> true`, activation, production candidate, and release
readiness are independent transitions. No roadmap date, benchmark target,
passing v0 test, or architecture decision may promote them implicitly.
