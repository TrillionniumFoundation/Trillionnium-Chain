# M13 State Sync, Light Client and Migration technical specification v1

Status: candidate implementation contract, with planned native multi-epoch
installation and transport. Primary module: M13; no new trust anchor is issued here.

## Authority

M13 verifies proof meaning and installs only authenticated state into bounded
staging. It cannot choose a fork, trust the peer majority, turn a QC into finality,
or migrate old signing authority into a new network.
Use [v0 light-client specification](../protocol/poco-bft-v0/06-light-client.md),
[AI-v1 specification 09](../protocol/poco-ai-native-v1/09-light-client-state-sync-and-upgrades.md),
and [staging admission contract](../architecture/TRNM_STATE_SYNC_STAGING_ADMISSION_V0.md).
V0 and AI-v1 proof/hash/tree formats are distinct; unknown profile never falls back.

Current generic components are `trillionnium/crates/trnm-state-sync-v0/src/lib.rs`
and `trnm-migration-v0/src/lib.rs`. Their verifier/installer traits are host
obligations, not actual transport or native proof implementation by themselves.
The state-sync crate now also owns a bounded, transport-neutral byte boundary:
`SnapshotTransferFrameV0::{encode_v0,decode_v0}` emits and consumes canonical
`TSYN` v0 manifest/chunk frames. This closes framing and pre-allocation checks
for a future peer adapter; it does not open a socket, choose a peer, or issue a
trust anchor. Decoded manifests still require an independently verified trust
path, and decoded chunks still require the session's exact manifest binding.
The current native lab h1-h3 sync route is bounded laboratory behavior, not
the generic arbitrary-height/multi-epoch protocol designed below.

The migration core now also exposes a bounded authenticated incremental-state
seam in `trnm-migration-v0`: `derive_incremental_delta_v0` computes a strictly
ordered delete/put delta between two target row sets while independently
recomputing both roots; `apply_incremental_delta_v0` verifies the plan/schema,
base rows digest/root, operation digests, delta Merkle root, target row digest
and target root before returning the applied rows. Deletes and empty values
are distinct, authority namespaces remain forbidden, and the delta has an
independent one-million-row bound. This is a deterministic projection and
verification primitive, not a database rewrite, network transport, garbage
collector, or production multi-host acceptance. A bounded SQLite adapter,
`SqliteIncrementalStateStoreV0`, now supplies a concrete staging/install seam:
it initializes a closed-world schema, applies one delta in an immediate
transaction, and reopens to verify generation, rows digest, target root and
last-delta digest, with the integrity-boundary reopen path independently
recomputing the root from durable rows. It rejects plan/schema substitution
and stale base state.
It remains a candidate integration adapter; an M07-owned deployment must still
bind its namespace/retention policy and pass crash, disk-full, replacement,
space and multi-host campaigns before claiming production installation.

The adapter's durability boundary is explicit: every connection requires the
expected application id, schema version and exactly the two migration tables,
configures SQLite WAL with `synchronous=FULL`, and opens each install with
`BEGIN IMMEDIATE`. A committed metadata/root update is recovered from the WAL
after an ordinary process restart; a writer killed after row mutation but before
metadata update is rolled back by SQLite and readback keeps the prior
generation/root. The repository test
`sqlite_process_kill_rolls_back_uncommitted_delta` exercises this with a real
child process and `SIGKILL`, then independently reopens the same file and
recomputes its root. This is process-crash evidence only: it does not claim
physical power-loss, disk-full, filesystem-corruption, or cross-host durability.
Schema/journal mismatches fail closed; opening a missing or partially-created
path never repairs it. A deployment still needs externally administered
fault-injection or physical power-loss evidence and a bounded disk-exhaustion
campaign before enabling replacement or cutover.

The adapter also exposes a bounded local handoff pair:
`export_snapshot_v0` emits `DurableDeltaSnapshotV0` only after metadata, ordered
rows, row digest, and target root have been read back and independently
recomputed. `initialize_from_snapshot_v0` validates the snapshot digest, row
ordering, authority-namespace exclusions, row digest, target root, and integer
bounds before creating a new closed-world store; it rejects an existing path and
checks every field again after the commit. Snapshot generation and the last
delta digest are retained, so an import/export round trip is byte-equivalent at
the protocol object level. This is an authenticated-by-caller staging artifact,
not a finalized source export, peer trust path, network protocol, tombstone
collector, or signer/finality handoff. A production transfer must bind the
snapshot to a verified checkpoint/export and exercise interrupted transfer,
disk-full, replacement, retention, and multi-host evidence separately.

## Interfaces

| Type / port | Meaning and owner |
|---|---|
| `WeakSubjectivityAnchorV0` | Trusted chain/protocol, epoch/height, checkpoint and validator-set digests; provisioned independently of peers |
| `CheckpointLinkV0` | Increasing checkpoint coordinate, state root, current/next set, parent checkpoint, finality proof and derived link digest |
| `CheckpointProofVerifierV0::verify_link` | M01/M02 actual proof verification; returning success from a stub is not acceptance |
| `VerifiedTrustPathV0` | Non-public construction after all path checks; authenticates terminal checkpoint |
| `SnapshotManifestV0` | Exact terminal root/schema/checkpoint, chunk count/max/total, chunk root and manifest digest |
| `SnapshotTransferFrameV0` | Canonical bounded `TSYN` v0 manifest/chunk frame; exact length, kind, digest and trailing-byte checks before session admission |
| `StateRootRecomputerV0` | M07 selected schema decoder/tree recomputation, not trusting advertised root |
| `NonDestructiveInstallTargetV0` | M07 staged writes and expected-current-root CAS, preserving old authority |
| `VerifiedSnapshotV0` | Complete proof-bound snapshot capability; cannot be issued from an incomplete download |

`Digest32V0::hash` in this candidate module uses SHA-256 with big-endian u64
length-prefixes for domain and each part. It is not the consensus CEV0 digest
function. Checkpoint link fields use their exact `canonical_digest` order;
`SnapshotManifestV0::chunk_binding_digest` excludes chunk_root/manifest_digest
to avoid a self-reference. The final manifest digest binds header digest plus
chunk root. Chunk digests bind the manifest header, index and exact bytes.
Do not substitute JSON ordering, a different Merkle construction or AI SMT roots.

`SnapshotTransferFrameV0` uses a 10-byte header (`TSYN`, version, kind, big-endian
payload length). Manifest payloads are capped at 256 KiB; chunk payloads are
capped at the 4 MiB module chunk limit plus the fixed framing fields. Manifest
frames carry all twelve manifest fields in the order above. Chunk frames carry
the manifest binding digest, index, declared byte length, exact bytes and chunk
digest. Decode rejects an unknown version/kind, truncation, trailing bytes,
noncanonical digest, zero/oversized payload or length arithmetic failure before
the frame can enter `StateSyncSessionV0`. The codec is deliberately not a
network protocol: peer identity, request deadlines, retries, checkpoint proof
selection, durable resume and multi-host agreement remain host-owned.

### Implemented native PoCO trust adapter

`trillionnium/crates/trnm-state-sync-v0/src/native_trust_v1.rs` provides the
strict native producer of `VerifiedNativeTrustPathV1`. This is a separate route
from a generic `CheckpointProofVerifierV0` callback and has no success stub.
`NativeTrustAnchorV1::from_pinned_bytes` exact-decodes the header, validator set
and parameters, validates all Ed25519 keys and context fields, and checks their
length-framed domain hash against an independently configured pin. The anchor
must have positive height and a nonzero state root; native epoch zero is valid.
The existing generic `WeakSubjectivityAnchorV0` still rejects epoch zero.
Anchor freshness/provenance remains an operator trust decision; a peer cannot
establish it by supplying its own matching hash.

`NativeTrustStepV1::Ordinary` carries exact proof bytes and an untrusted target
expectation. Its parent ID/height/timestamp must equal the current authenticated
header, its height must advance exactly one, and strict three-chain verification
uses only the current set/parameters. `EpochFirst` also carries all eight epoch
evidence preimages. Strict epoch verification must return the exact current
checkpoint header, its first new target is checkpoint height + 3 through the
two old seals, and its epoch advances exactly one. The returned authenticated
new set/parameters become the sole context for following steps. Signed TCs
permit skipped views without skipping any of these height or checkpoint joins.

Before signature work, nonempty paths are bounded to 4,096 links and 64 MiB
aggregate proof/evidence bytes, or smaller caller limits; anchor bytes have a
4 MiB ceiling. Each decode retains the intrinsic CEV0 root ceiling, and a single
mutable CEV0 signature-work budget spans all links without failure refunds.
Overflow, missing bytes, wrong pin/context, disconnected step, exact-decode or
strict-finality errors issue no verified capability.

The private result exposes its terminal header, set/parameters and
`snapshot_trust_path()`, a `VerifiedTrustPathV0` projection whose chain/protocol,
link digests, epoch/height/state root and finality evidence all derive from the
verified native path. Existing `SnapshotManifestV0::validate` and staging can
consume that projection. This implements proof and target authentication;
network download, native state recomputation and a durable installer still
require their concrete composition. It does not migrate or activate a signer.

The candidate native session composition is now explicit in
`NativeStateSyncSessionV1`. `NativeApplicationCheckpointV1` requires a nonzero
application schema digest and monotonic application version. Session admission
binds those facts to the native trust-path digest, terminal block ID,
checkpoint digest, manifest digest, terminal epoch/height and state root in a
single `NativeStateSyncBindingV1`; the binding digest is the persistence key.
This prevents a verified proof from being reused with another application
schema/version or a manifest from another terminal checkpoint. The wrapper
retains all generic bounds and chunk substitution checks and returns a
`NativeVerifiedSnapshotV1` that carries the same binding after recomputation.

Restart is a proof revalidation operation, not a bitmap restore. The session's
`NativeStateSyncReadbackV1` records binding/manifest identity, retained byte
count, chunk count and a content-derived progress digest over sorted
`(index, chunk_digest)` pairs. `resume` requires the same freshly verified native
path, exact manifest, application facts and every retained chunk; changed bytes,
binding, schema/version or progress are rejected before a verified snapshot is
issued. Tests cover successful interrupted-resume, chunk substitution and
tampered readback.

`SqliteNativeStateSyncStoreV1` now persists that boundary in a closed-world
SQLite database. It sets an application ID, schema version, WAL journal and
`synchronous=FULL`; initialization rejects an existing path. The metadata row
stores every `NativeStateSyncBindingV1` field, the manifest chunk-binding
digest, and the exact readback. A separate WITHOUT ROWID chunk table stores
immutable `(index, manifest_binding, bytes, chunk_digest)` rows. Every open,
readback and resume rechecks the schema/table set, binding canonical digest,
chunk bounds, chunk digest, sorted-index progress digest, byte/count totals and
metadata equality. `append_chunk_v1` validates against a cloned in-memory
session, writes the chunk and readback in one immediate transaction, and only
then advances process-local state; a different payload at an existing index is
`ChunkSubstitution`.

`resume_existing_v1` still requires a newly verified `VerifiedNativeTrustPathV1`,
exact manifest and application checkpoint. The database is therefore a crash
resume record, not a trust anchor or peer-selected source. The repository
test `native_sqlite_session_survives_cross_process_restart_and_rejects_readback_tamper`
closes a real child-process reopen and rejects a modified durable progress
digest. This is process-restart evidence only; it does not establish physical
power-loss, disk-full, filesystem-corruption, peer transport, signer, or
multihost durability, and it does not authorize production installation.

`native_trust_v1_tests.rs` covers real signed ordinary-to-epoch paths for normal
and fallback handoff, signed TC views 3/5/8, snapshot target substitution,
checkpoint-byte mismatch, peer-set replacement, replay/reordering, signature
corruption, aggregate limits and work exhaustion. It also proves explicit
positive-height native epoch-zero admission while the generic rule stays closed.

### Owned compatibility receipt types and verifier

`trnm-finality-types` supplies `SignedCommandEnvelopeV1`, validator/header/vote/QC
types and `FinalityReceiptV1`; `trnm-finality-verifier::verify_finality_receipt`
is its node-independent consumer. The receipt binds schema/chain/command,
transaction hash/index, block height/hash/header, state/transaction roots,
optional object reference, transaction/object inclusion proofs, validator-set
ID, a QC and receipt hash. An object reference binds key/type/version/value hash.
The types' exact signing/hash helpers in `src/protocol.rs` and `crypto.rs` are
the compatibility encoding authority; these serde types are not frozen CEV0
finality objects and cannot be decoded as such merely because both say v1.

This verifier authenticates one receipt-bound QC and membership proofs under
the supplied trusted validator set. It does **not** establish frozen PoCO-BFT
three-chain/epoch finality. Validate chain/header/root/hash/set correspondence,
QC target and signatures, receipt hash and every required inclusion path.
`MerkleProofV1` carries domain, leaf hash/index/count and directional siblings;
the duplicate-last tree checks exact path direction, odd-width self-padding,
missing/trailing steps and root. Transaction and object domains are respectively
`trnm.transactions.v1` and `trnm.state.objects.v1`, using parent domain
`trnm.merkle.parent.v1`. The root does not independently commit leaf count;
path consistency must not be advertised as authenticated exact tree size.

Compatibility errors are `anyhow` failures, not a stable consensus wire enum.
The planned compatibility API boundary classifies decode/bound, context,
signature/quorum and membership failures while retaining detailed local cause;
all failures issue no verified result or state mutation. Its selected host caps
are 1 MiB receipt JSON, 256 validators and 64 siblings/path, checked before
allocation. These are new adapter limits, not claims that the current serde
decoder automatically enforces them. Unknown schema/set cannot fall back to a
different profile. Replay `public_receipt_verifier_checks_transaction_domain_and_index`,
`rejects_proof_domain_and_path_shape_mutations` and
`duplicate_last_format_does_not_independently_authenticate_leaf_count`.

### Owned bounded AI Order verifier

`trnm-poco-order-finality-verifier-v1` independently decodes and re-encodes the
exact CEV1 `FreshGenesisTrustBundleV1` and `OrderFinalityProofV1`. The external
pin is SHA-256 of the exact trust-bundle bytes, not a peer-selected trust root.
`verify_pinned_fresh_genesis_order_finality_v1` restricts the finalized target
to FreshGenesis. `verify_pinned_direct_order_finality_v1` also permits an
ordinary target selected by committed finality-chain length, retaining only
the independently verified direct parent/height/view ancestry. Both recompute
parameters/set/epoch/header/vote/QC identifiers and strict Ed25519 weighted
quorum. Timeout certificates and handoffs are unsupported by these narrow APIs;
general M13 trust-path design does not expand their current capability.

Existing parser maxima are trust bundle 64 KiB, Order proof 256 KiB, execution
binding claim 4 MiB/16 witnesses, 256 validators/certificate signers, 1,024-byte
consensus strings and 128-byte signature inputs. `ParserBound`, `Truncated`,
`TrailingBytes`, `NonCanonical` reject before issuing authority;
`PinnedTrustMismatch`, `InvalidSignature`, `UnderQuorum`, `InvalidChain` and
`InvalidTarget` reject proof meaning. The non-publicly constructed
`VerifiedOrderFinalityV1` then permits bounded application-state verification.
The execution-binding verifier additionally matches the canonical binding
object, membership and actual finalized Order root, not a claimed composite
root. `test-support` synthetic issuers must remain excluded from deployment.
Golden cases require one-byte trust-pin mismatch, a trailing proof byte, an
underweight QC, a valid QC over a disconnected parent, and substituted binding
object; each rejects without an authority carrier. Source tests are in `src/lib.rs`.

### Owned cross-plane readback join

`trnm-poco-cross-plane-readback-v1::fresh_join_cross_plane_v1` consumes five
store references and `CrossPlaneJoinRequestV1`: exact context/Order head/proof
digest, DA batch, task/lease/escrow/result/settlement identities and each terminal
receipt. It samples every store twice, requiring unchanged identities,
sequences/heights, Order heads, state roots, journal tails and lifecycle joins.
DA head and certificate are sampled together in a SQLite read transaction.
Only then issue `ConfirmedCrossPlaneReadbackV1` containing the exact projection
digest. `SourceChanged`, `OrderMismatch`, `StoreIdentityConflict`,
`LifecycleMismatch` and `DaCertificateMismatch` reject; they do not authorize
rollback or a best-effort partial projection.

This read-only join verifies stable co-observation, not a cross-database atomic
commit. Its supplied Order-proof digest is still a trust input. M08/M15 must
consume exact store IDs/sequences/roots/tails in their own authenticated CAS
before publication; a cached projection is insufficient after any source moves.
The selected planned host budget allows one join at a time, at most two retries
after source movement and a 5-second local deadline; no infinite stabilization
loop or state writes on failure. Reopen discards cached confirmation and joins
fresh. Acceptance must move one source between samples and require rejection,
swap an otherwise equal receipt from another store ID and require rejection,
and preserve all five stores when a source is unavailable. These are separate
tests from whole-node recovery; the latter remains an M08 obligation.

## State machine

### Trust path and light-client verification

1. Load a trusted earlier anchor from authenticated configuration/checkpoint
   custody. Its provenance/freshness must be verified independently of the proof.
2. Generic `WeakSubjectivityAnchorV0::validate` rejects zero identities, height
   and epoch; genesis bootstrap needs its separate commissioned route.
3. `verify_trust_path_v0` requires 1..4,096 links, exact chain/protocol/parent
   digests, strictly increasing heights and legal epoch progression. Current
   generic links allow same epoch or its direct successor, not a silent epoch jump.
4. Verify exact expected current/next validator-set binding and each link digest.
5. Invoke the real proof verifier for every link. It checks weighted signatures,
   frozen three-chain/TC/epoch rules and old/new trust contexts, not only a proof hash.
6. Issue `VerifiedTrustPathV0` only after all links pass. Missing history returns
   unavailability; inconsistent authenticated checkpoints halt trust advancement.

Expose four distinct products: ordering finality, application membership,
artifact availability, and result/settlement maturity. A valid proof in one
class cannot satisfy another. Native JMT membership and AI-v1 256-sibling
state proof use their respective exact key-bit/sibling rules.

### Planned finalized transaction proof adapter

The native-byte portion of the [M05 V1 proof contract](M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md#planned-v1-multi-transaction-proof-contract)
is implemented in `trnm-tx-lifecycle-v0/src/finalized_proof_v1.rs` against
native target-header payload/receipt roots and strict oldest-target finality. The two ordered branches share index/count but use different frozen
root-kind domains. Receipt membership authenticates gas/fee/events and payload
binding. Full M05 tx_id inclusion additionally requires the native adapter to
commit the entire signed intent or its complete verified tx_id; lossy payload
extraction supplies only native inclusion and local correlation. It does not
authenticate an intermediate transaction state root or an
uncommitted outcome string. Return a private verified inclusion capability to
M05/M14 only after all checks; proof absence is unavailable, never a trusted
zero digest. Full M05 intent-to-native binding and public response composition
remain planned, separate from generic snapshot verification.

### Download, verification and installation

`StateSyncSessionV0::new` validates manifest against the verified terminal link.
Require every bound and exact digest before accepting chunks. `accept_chunk`
checks index, declared bytes and binding; identical duplicate is idempotent,
different bytes for a retained index are `ChunkSubstitution`.
`verify_complete` requires every index, exact total bytes and recomputed chunk
root before invoking schema-aware state-root recomputation. Root disagreement
cannot issue `VerifiedSnapshotV0` even if all chunk checksums match.

Transport adapters must decode each complete frame with
`SnapshotTransferFrameV0::decode_v0` before enqueueing it. A manifest frame is
then passed to `StateSyncSessionV0::new` with the locally verified trust path;
each chunk frame is passed to `accept_chunk`. A frame that decodes correctly but
names another checkpoint, epoch, chunk binding or session is rejected by those
second-stage checks. The adapter must retain only accepted bytes, rehash retained
chunks on restart, and request missing indices; frame decoding alone never
certifies a finalized state.

Installation binds nonzero `StagingIdentityV0` generation/digest and exact
expected current root. Write only to new staging, verify again, then use
`commit_staging_cas`. The install receipt must match expected source, target
and staging identity. Another owner moving the root causes CAS rejection;
never overwrite that successor because the downloaded snapshot is newer.

### Planned native multi-epoch snapshot binding

Persist M08's distinct `consensus_tip` and `application_head` coordinates.
At checkpoint C, seals C+1/C+2 do not create application versions, P rows or
receipts. A snapshot may contain application checkpoint C while proving the
later consensus seal-2 tip. It must include the exact independently verified
`AuthenticatedEpochApplicationEdgeV1` if it will execute the first new block.

Verify the old checkpoint, two seals, joint handoff, old/new configurations,
checkpoint application root/version/commit sequence, terminal seal parent and
first target C+3 before installing edge metadata. M07's planned
`CarriedRootReaderV1` redirects only empty root lookup C+2 to the authenticated
root at C. Child node references retain real versions; value lookup at C+2
must establish no writes in the gap. This is private construction metadata,
not a claimed seal application state. The first real new application version
is C+3. Reopen reauthenticates edge and predecessor before allowing that view.
Unknown edge schema or unsupported live epoch phase remains disabled.

### Migration, not ordinary state sync

`verify_export_v0` accepts `FinalizedExportHeaderV0`, canonical export rows and
a real `SourceFinalityVerifierV0`. It checks ordered unique namespace/keys,
counts/roots, source context and forbidden authority namespaces.
`project_and_recompute_v0` applies an exact versioned `TargetProjectorV0`
and independently selected `TargetRootBuilderV0`, retaining liabilities.
`MigrationPlanV0` binds the source export, target schema/genesis and recomputed
projection; `verify_cutover_agreement_v0` verifies the exact signer agreement.

Never import `validator_signing_state`, `consensus_private_key`, `signer_journal`,
`safety_store`, `remote_signer_watermark`, `node_commit_ledger`, or
`operator_recovery_key` namespaces, including their reserved prefixes.
Target gets fresh identity/signing custody. A new genesis is not permission
to discard escrow, challenge, refund or retention liabilities. Preserve each
liability's source ID, asset/value, owner, deadline and authenticated target
mapping; reconcile per-asset totals before any cutover. Unknown source types
reject migration instead of being silently omitted.

## Persistence and recovery

Persist anchor/manifest/schema identities, validated chunk bitmap/digests,
staging generation and expected-current root with bounded journal records.
On restart, revalidate retained bytes against the same manifest and proof;
the bitmap alone cannot certify data. Resume missing chunks only.

Before install commit, failure may abort the valid owned staging namespace,
preserving the old store. After a possibly applied `commit_staging_cas`, **do
not abort staging**: fresh-read the target and decide exact source or target.
An uncertain swap followed by blind cleanup could delete installed authority.
Partial/conflicting receipts halt installation until reconciled by M07/M08.
Do not reopen a signed older snapshot to repair an externally newer signer state.

## Resource bounds

Existing generic ceilings are 4,096 trust links, 65,536 chunks,
4 MiB/chunk and 512 GiB nominal snapshot bytes. The additional
`chunk_count * maximum_chunk_bytes` check makes the effective maximum under
those chunk limits 256 GiB; both checks remain required. Total bytes must be
at least chunk count because chunks are nonempty, and arithmetic is checked.

Select planned **SYNC-DEV-1** host limits: 1 GiB snapshot, 1 MiB/chunk,
1,024 chunks, 256 links per request, 4 concurrent chunk downloads and 2 peers,
5-second request timeout, 2 retries/peer, and 2 GiB reserved staging disk.
Smaller host budgets return local unavailability, not invalid consensus proof.
A trusted anchor must be within a signed profile's maximum age; development
policy selects at most 2 epochs behind an independently trusted current epoch.
Without a fresh independent reference the node requests a new anchor and stays
non-signing. Peer-reported height or wall-clock time cannot supply that reference.

Migration ceilings remain the source constants: 100,000,000 rows, namespace
128 bytes, key 64 KiB, value 16 MiB and 1,024 cutover signers. Development
host additionally caps total export bytes at 1 GiB and rows at 1,000,000.
The signed deployment profile fixes both codec/proof versions, trusted anchors,
schema/projector digests, target context, limits, install namespace and recovery
policy. Missing values or limits above module ceilings reject commissioning.

## Security

`InvalidTrustAnchor`, `InvalidTrustPath`, `ManifestTrustMismatch` and
`InvalidManifest` reject authority/binding before installation.
`InvalidChunk`, `ChunkSubstitution`, `SnapshotTooLarge`, `ChunkRootMismatch`,
`StateRootMismatch` preserve the old authoritative store.
`IncompleteSnapshot` is incomplete work, not evidence of a bad finalized root.
`InvalidStagingIdentity`, `InvalidExpectedCurrentRoot`, `InstallReceiptMismatch`
fence the attempted installation. Host adapter failures retain their nested
class; local timeout/disk-full does not become peer Byzantine invalidity.

Path traversal, symlink/namespace replacement and archive bombs are rejected by
bounded M07 adapters. Downloaded filenames never become arbitrary local paths.
No peer message can trigger a shell/projector binary selected by the peer.
Proof verification work, including failed signatures, is charged before work.

## Observability and SLO

Report verified links/chunks/bytes, missing-chunk count, per-peer timeout/budget
refusals, trust-anchor age, staging disk, recomputation/install duration and
source/target readback result. Separate downloaded from verified and installed.
SYNC-DEV-1 accepts only if interrupted installation always preserves an exact
source or target; throughput is measured on the declared state size/topology.
Sensitive state data and authority keys are not copied into diagnostic logs.

## Verification and evidence

| Case | Input and exact expected result |
|---|---|
| M13-ANCHOR | All-zero or epoch-0 generic anchor: `InvalidTrustAnchor`; proof cannot choose its own anchor |
| M13-PATH | Link parent differs or height does not increase: `InvalidTrustPath` before proof adapter invocation |
| M13-CHUNKS | Manifest 2 chunks/3 total bytes: both nonempty exact chunks needed; missing one→`IncompleteSnapshot` |
| M13-SUB | Supply two different payloads at index 0: `ChunkSubstitution`, prior staged chunk retained |
| M13-ROOT | Valid chunk hashes but different recomputed application root: `StateRootMismatch`, no capability/install |
| M13-FRAME | Canonical manifest/chunk frame round trip; unknown version, trailing byte, altered payload digest and over-limit frame reject before session admission |
| M13-LOSS | Install CAS succeeds, acknowledgement lost: read target, never invoke precommit abort |
| M13-EPOCH, planned | App checkpoint 100, consensus seal-2 102, first target 103: verify edge; no fake app 101/102; swapped checkpoint root rejects |
| M13-MIGRATE | Export namespace `signer_journal/...` or omit funded escrow liability: reject before target activation |

Replay existing `tests/verification_seals.rs` functions
`invalid_path_cannot_reach_the_proof_adapter_or_issue_a_result`,
`recomputed_root_mismatch_cannot_issue_a_verified_snapshot`, and
`chunk_commitment_mismatch_is_rejected_before_root_recomputation`.
`tests/staging_admission.rs::uncertain_commit_never_aborts_staging` covers the
cleanup boundary. Generic fixture proof adapters are not independent native
crypto verification; acceptance also requires real M01/M02 proofs and M07 install.

### Candidate T1 ordinary finalized-body replay (primary M13)

The first executable public-native receiver starts from an independently pinned
canonical application genesis, validator set, parameters and client signer policy.
It never imports peer command IDs, nonce sets, local commit IDs or store checksums:
the frozen header state root does not authenticate those replay sets. Each record
contains exact finality CEV0 bytes and the original signed outer transaction bytes;
strict finality, contiguous parent identity/time, and actual native execution must
all agree before SQLite commit. Only height 1 may use the existing explicit trusted
genesis decoder. Epoch changes, checkpoint/seal blocks and schema 4/5/6
installation remain rejected by this initial schema-3 receiver; it issues no
signer capability.

The bounded candidate transfer is at most 128 ordinary finalized records, 1 MiB
per record, 64 MiB total, and 64 KiB per download chunk. A manifest pins the chosen
height, target block ID, each record length/hash and the hash of every 64 KiB chunk.
The manifest is limited to 128 KiB; chunk hash/cardinality are checked before
persistence and rechecked on resume. A wrong same-length peer chunk never occupies
an immutable slot, so the correct retry can succeed. These hashes detect transfer
substitution; consensus proofs and execution provide authority. The client selects
an exact positive target height, so a server cannot silently claim a shorter prefix.
Persist the manifest and immutable chunks with create-new, file and directory sync.
On restart re-read every used chunk and verify its exact hash, then compare the real
application committed head with the replayed prefix. A crash after application
commit but before progress publication resumes from that exact committed head.

The receiver crash contract requires real child-process `SIGKILL` tests at
manifest persistence, partial chunk write, chunk file sync/link/publication,
native P before finalized commit, native K before CURRENT, and CURRENT file
sync/link/publication. Each parent must observe the selected cut before killing
the child, assert signal 9 (no normal shutdown), reopen the same stage, recheck
persisted hashes and native committed rows, and complete honest replay with the
same semantic head. Exact retries must retain committed transaction dedup;
forged chunks/proofs must not replace the prefix or acquire publication. These
are local process/storage recovery tests, not power-loss, cross-epoch, signing
activation or fleet fault/performance acceptance. Fault hooks are test-only.
`native_replay_sigkill_matrix_v1` exercises all ten cuts using actual finalized
records from the signed-client/WAL/four-owner execution path; its child helper
is compiled only in the test binary. The P cut confirms K is still height 3;
the K cut confirms height 4 before replay resumes to the target. A forged proof
with recomputed transfer hashes is rejected in a separate stage after the K cut,
while the honest stage retains its original progress.

A private, locked receiver directory owns at most two staging directories, keyed
by manifest digest, and a final CURRENT record. A valid-shaped but unauthenticated
first peer manifest cannot pin the only download slot: an honest retry can choose
the second stage without deleting any verified application progress. A third
distinct manifest reports capacity exhaustion and requires an explicitly chosen
fresh replica directory. A completed replica keeps its selected stage. CURRENT is published only after the complete target is strictly verified,
the application owner is dropped, and a freshly reopened schema-3 owner confirms
the exact head. CURRENT includes the selected application directory. It identifies an application replica only: Core, SafetyRules, independent
watermarks and signing stay uncommissioned. The actual socket executes proof/sync
reads through two bounded workers, so a
128-file manifest read does not occupy the consensus actor. Individual requests
retain an 8-second client deadline and one sync download has a 600-second bound.
Source export stops after height 128, and any record larger than 1 MiB reports
sync unavailable without invalidating an otherwise valid consensus block. These
are candidate transfer limits, not a hard SQLite disk quota or production SLO.
Missing files, altered chunks, conflicting manifest, unsupported epoch, invalid proofs or execution mismatch retain the staged
state and return an error; no invalid input is treated as an empty or virgin store.

### Ordinary proposal synchronization without a signing side effect (M13-ORDINARY-SYNC-V1)

The live laboratory receiver has a second, deliberately narrower path for a
proposal that arrived after the local vote/timeout owner was already released.
This path is now an implementation contract rather than an unnamed fallback. It
is entered only after `receive_unbound_proposal_v1` has authenticated the
proposal and its certified parent and returned no voting owner, and only while
the phase is `Ready`. A `VoteSigned` or `TimeoutSigned` owner is never consumed
by this operation.

The exact operation is:

1. `vote_ready_proposal_v1` clones the inert proposal for the admission queue;
   the queue retains the authenticated body and route. Stale proposals whose
   justify tuple is below the local high QC remain `IgnoreStale` and do not
   reach execution.
2. `sync_late_proposal_v1` rechecks the authoritative parent binding, height,
   block ID, timestamp and route, then calls
   `PocoNodeLabOrdinaryProposalRuntimeV0::drive_one_to_synced_no_sign_v0`.
3. The runtime performs `Input::SyncedProposal`, Safety persistence and exact
   `StorageAck`, one `ValidateSyncedPayload` claim, native P reservation and
   durable execution, and the application-sealed Core D transition. The final
   Core ACK must have an empty effect list; it cannot mint a Vote, Timeout or
   signer intent.
4. M03/M08 persist the distinct `SyncedNoSign` Safety-C/K closure and an
   independent whole-node checkpoint. The checkpoint compares the fresh Safety
   head, application head, P/K artifact digests and signer watermark before and
   after the operation. The runtime then returns to `Ready` and records the
   execution artifact for later finalization/readback.

The implementation symbols are
`trillionnium/crates/trnm-poco-lab-validator/src/continuous_runtime.rs::sync_late_proposal_v1`,
`...::vote_ready_proposal_v1`, and
`trillionnium/crates/trnm-poco-node/src/lab_authority.rs::drive_one_to_synced_no_sign_v0`.
The SQLite adapter is
`trnm-native-application-sqlite/src/store.rs::acknowledge_confirmed_synced_no_sign_v0`;
the K/checkpoint adapter is
`trnm-poco-node/src/external_node_checkpoint.rs::advance_native_k_whole_node_synced_no_sign_checkpoint_v0`.
The operation is covered by the real SQLite/native test
`ready_synced_proposal_commits_without_vote_or_watermark_advance_v1` and the
node integration test
`synced_proposal_commits_without_creating_a_signer_intent`.

Failure and recovery are closed as follows: any parent/route/digest mismatch
fences the runtime before application mutation; an uncertain P, Safety, K or
checkpoint write is resolved by exact source/target readback; a signer
watermark change or pending intent fails the checkpoint join; and a duplicate
block identity is idempotent only when all retained bytes and bindings match.
The operation is an ordinary proposal execution/readback path, not a finality
certificate, public production state-sync protocol, epoch activation, or
permission to sign. Cross-epoch transfer still requires the authenticated
M08/M07 edge and the multi-host acceptance described below.

## Activation boundary

Commissioned public synchronization needs authenticated transport, general
native proof paths, real state recomputation/installer, bounded restart and
multi-epoch producer/consumer tests. Migration additionally requires exact
source finality, liabilities, target-root and fresh-custody agreement.
The general multi-epoch installer remains planned; the bounded ordinary application
replica above is an explicit candidate capability with signing disabled.
