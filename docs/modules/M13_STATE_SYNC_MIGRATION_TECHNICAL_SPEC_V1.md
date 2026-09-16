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
The current native lab h1-h3 sync route is bounded laboratory behavior, not
the generic arbitrary-height/multi-epoch protocol designed below.

## Interfaces

| Type / port | Meaning and owner |
|---|---|
| `WeakSubjectivityAnchorV0` | Trusted chain/protocol, epoch/height, checkpoint and validator-set digests; provisioned independently of peers |
| `CheckpointLinkV0` | Increasing checkpoint coordinate, state root, current/next set, parent checkpoint, finality proof and derived link digest |
| `CheckpointProofVerifierV0::verify_link` | M01/M02 actual proof verification; returning success from a stub is not acceptance |
| `VerifiedTrustPathV0` | Non-public construction after all path checks; authenticates terminal checkpoint |
| `SnapshotManifestV0` | Exact terminal root/schema/checkpoint, chunk count/max/total, chunk root and manifest digest |
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

## Activation boundary

Commissioned public synchronization needs authenticated transport, general
native proof paths, real state recomputation/installer, bounded restart and
multi-epoch producer/consumer tests. Migration additionally requires exact
source finality, liabilities, target-root and fresh-custody agreement.
The general multi-epoch installer remains planned; the bounded ordinary application
replica above is an explicit candidate capability with signing disabled.
