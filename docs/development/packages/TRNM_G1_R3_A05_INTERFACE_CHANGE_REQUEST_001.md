# ICR-G1-R3-A05-001 — remote signer intent and external checkpoint custody

Status: **proposed** (not accepted; A03 must not edit A05-owned surfaces)

## Request identity

```text
request_id = ICR-G1-R3-A05-001
requester_agent = A03
requester_package = G1_R3_ORDINARY_PROPOSAL_AUTHORITY_V1
owner_agent = A05
owner_package = G1_R4_SAFETY_CHECKPOINT_V1
created_at = 2026-08-29
```

## Source and current boundary

```text
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_driver_boundary = CandidateEffectDriverHooksV1::{
    compare_and_advance_whole_node_checkpoint_v1,
    sign_v1
}
current_custody = feature-gated FileHooksV1 test key; no remote signer receipt
current_acceptance = candidate-only; no accepted A05 interface digest
```

The ordinary driver can currently receive a Core-owned canonical signing
intent, but its test adapter signs with a process-local fixture key and its
checkpoint callback is not an external anti-rollback authority.  A03 cannot
turn either callback into production custody or edit the A05 signer,
SafetyStore, watermark, or checkpoint modules.

## Requested interface

A05 should expose an additive, versioned, node-owned capability equivalent to:

```text
RemoteSignerIntentCustodyV1::authorize_and_sign(
    exact_intent: CanonicalSignIntentV0,
    predecessor: WholeNodeCheckpointPredecessorV1
) -> Result<RemoteSignedIntentReceiptV1, RemoteSignerOutcomeV1>
```

The receipt must be opaque, non-`Clone`, non-serializable, and consumable only
by the same live Core/driver authority that supplied the intent.  It must bind
the exact canonical signing root, intent kind, chain/genesis, epoch, view,
height/block or timeout target, validator-set/profile commitment, author,
Safety revision, and external checkpoint predecessor.  A03 must never receive
or store a raw private key.

Required outcomes are explicit and non-interchangeable:

```text
Signed             # one exact intent was durably authorized and signed
PolicyRejected     # the exact intent is not authorized; no signature emitted
Unavailable        # signer/checkpoint source is unavailable; retryable only
CommitAmbiguous    # durable signer/checkpoint response was lost; recovery fence
CorruptOrConflicting # identity, root, WAL, watermark, or readback mismatch; stop
```

Before any remote signer request, the owner must durably record the exact
intent and advance an external monotonic checkpoint by compare-and-set with a
fresh readback.  The signer must reject a duplicate or lower checkpoint/root,
and a response-loss/restart path must resolve the exact prior intent rather
than issue a second signature.  The owner must bind the signer identity and
protocol/profile version, authenticate all response bytes, and preserve
`CommitAmbiguous` until a durable recovery decision.  No receipt may mint a
Core revision, Vote, finality proof, application commit, or network message.

## Compatibility and safety invariants

```text
new_authority_created = false until A05 acceptance
raw_key_in_A03_or_default_node = false
production_reachability_changed = false
lower_external_watermark_accepted = false
duplicate_signing_root_accepted = false
response_loss_silently_retried = false
```

The existing candidate hooks remain test-only compatibility adapters.  Once an
A05 receipt is accepted, A03 will add only the narrow consumer-side mapping
from `Signed` to Core's existing `SignatureReady` boundary; it will not change
Core signing rules, SafetyStore persistence, checkpoint formats, or signer
protocol semantics.

## Required vectors and downstream invalidation

Positive vector: one ordinary Vote intent whose exact root, revision, signer
identity, and predecessor checkpoint are recorded, remotely signed, read back,
and released to the driver after restart-safe reconciliation.

Negative/fault vectors: altered root/kind/height/view/block/epoch/set/profile;
foreign Core affinity; duplicate intent; lower/equal watermark; WAL truncation
or reorder; signer identity/key rotation; stale checkpoint; path/inode or
namespace replacement; signer timeout; response loss after durable sign; SIGKILL
before/after checkpoint CAS, signer call, response write, and readback; and
restart with an unresolved intent.

Acceptance invalidates all A03 signer/custody and process-Vote evidence that
uses the fixture key or local checkpoint callback.  A03 will rerun the exact
driver, process, restart, and independent replay gates against the accepted
A05 source commit/tree and interface digest.

## Required evidence before acceptance

```text
positive_vectors = exact canonical ordinary Vote intent + remote signer receipt
negative_mutants = root/context/authority/watermark/identity substitutions
fault_matrix = checkpoint/signer/response/restart SIGKILL cuts
exact_commands = clean-clone unit/process/replay commands with source hashes
independent_review = reviewer outside A03/A05; pending
```

## Review decision

```text
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = pending
accepted_interface_digest = pending
source_commit = pending
source_tree = pending
notes = A03 must not implement or edit A05 signer/checkpoint internals before acceptance
```
