# ICR-G1-R3-A02-001 — authenticated body/evidence replay handoff

Status: **proposed** (not accepted; implementation must wait for A02 owner
decision)

## Request identity

```text
request_id = ICR-G1-R3-A02-001
requester_agent = A03
requester_package = G1_R3_ORDINARY_PROPOSAL_AUTHORITY_V1
owner_agent = A02
owner_package = G1_R2_RECOVERY_CORE_ACK_V1
created_at = 2026-08-29
```

## Current authority and interface digest

```text
base_ref = refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829
base_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
base_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
current_interface_version = candidate-v1
current_interface = PayloadReplayBodyStoreV1::{open, admit, resolve};
                   PayloadReplayRecoveryOwnerV1::{status, recover_payload_publication,
                   acknowledge_core}; private CoreReplayRequestV1 /
                   ReplayToCoreAuthorityV1 coordinator binary
current_interface_digest = 5ac7ab4ac69c44b08b0aad7921b22a1b5f8b90836a4b57a9d9adf3e8fb533884
current_owner = A02
```

The digest is SHA-256 over the exact `sha256sum` output (including each path)
for the five current interface source files, in the order below, generated
with:

```bash
sha256sum \
  trillionnium/crates/trnm-consensus-peer-lease/src/payload.rs \
  trillionnium/crates/trnm-consensus-peer-lease/src/payload_body.rs \
  trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery/part_01_types.rs \
  trillionnium/crates/trnm-consensus-peer-lease/src/payload_recovery/part_02_owner.rs \
  trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-replay-to-core-coordinator-v1.rs \
  | sha256sum
```

The current candidate APIs are not an accepted A02 handoff: body resolution
still requires a live frame/receipt, does not expose a restart lookup by exact
target, and the Core acknowledgement coordinator remains a private candidate
binary with caller-supplied acknowledgement semantics.

## Requested interface

A02 should expose an additive, versioned, node-owned capability equivalent to:

```text
PayloadReplayRecoveryOwnerV1::resolve_authenticated_body_after_restart(
    exact_target: PayloadReplayRecoveryTargetV1
) -> Result<PayloadReplayResolvedBodyV1, PayloadReplayResolutionErrorV1>
```

The returned `PayloadReplayResolvedBodyV1` (or equivalent) must be opaque,
non-`Clone`, non-serializable, and consumable only by the owning node adapter.
It must carry authenticated, independently read-back facts for the exact
target: namespace/root identity, route/frame kind, record index and hash-chain
position, session and generation, sequence, payload length, body digest, chain
and genesis, epoch/validator-set, parent/context binding, and canonical body
and evidence bytes within fixed bounds (maximum frame 8 MiB, journal 256 MiB).

The storage owner must expose storage outcomes, while A03 owns semantic
ordinary-proposal validation.  Required outcomes are therefore distinct:

```text
AuthenticatedBody       # exact bytes and storage metadata were read back
Unavailable                 # missing/transient source; retryable
CorruptOrConflicting       # safety stop; never downgrade to either outcome
CommitAmbiguous            # publication may have committed; recovery required
```

A03 maps an `AuthenticatedBody` through the frozen body, commitment, parent,
validator-set, parameter, and runtime-profile checks to `Sealed` or
`DeterministicallyInvalid`; it maps `Unavailable` to the explicit retryable
Core result and treats `CorruptOrConflicting`/`CommitAmbiguous` as a stop.

The owner must revalidate lock/path/inode/head identity and exact hashes after
read.  Metadata and body journals must be opened and read under one composite
owner (or an equivalent atomic consistency protocol) so a target cannot be
resolved from split-brain metadata/body heads.  The owner must preserve
response-loss/restart ambiguity until a durable decision, and never mint a
Core revision/acknowledgement, Safety authority, signer intent, or raw key.
Existing private Core receipt constructors and sealed authority boundaries
must remain private.

### Frozen capability details

```text
semantic_version = 1 (candidate additive handoff)
canonical_domain = trnm.consensus.payload-replay.resolved-body.v1
canonical_bytes = exact authenticated body bytes plus independently encoded
                  target/namespace/frame metadata; no caller-provided digest
issuer = A02-owned replay/body store and recovery owner
caller_authority = A03 may consume only the returned opaque ticket
linearity = non-Clone, non-Serialize, private constructor, one consumer
bounds = frame <= 8 MiB; journal <= 256 MiB; bounded metadata/depth/counts
exact_errors = Unavailable | CorruptOrConflicting | CommitAmbiguous
               (no downgrade or implicit retry)
compatibility = existing resolve/ack APIs remain explicit and reject a
                 mismatched route, namespace, generation, or target
```

## Safety rationale and compatibility

```text
new_authority_created = false
production_reachability_changed = false
signing_or_settlement_authority_changed = false
serialization_boundary_changed = false
```

The request is needed because A03 cannot safely replace the synthetic ordinary
process fixture without a restart-safe body/evidence source. A caller-supplied
body or inert digest would permit root/context substitution and would violate
the Core/native parent binding. Existing callers must remain explicit and
must reject the new capability when namespace, route, generation, or profile
does not match.

## Required vectors and downstream invalidation

Positive vector: one authenticated non-empty ordinary Proposal body and
evidence bundle, resolved after a restart, with exact parent/JMT/validator-set,
parameter, and runtime-profile bindings.

Negative/fault vectors: body or metadata hash/index/fingerprint mismatch;
missing, truncated, malformed, or oversize body; wrong namespace, epoch,
validator set, parent, context, sequence, or profile; duplicate/conflicting
frame; append/head lag; response loss and SIGKILL at each publication cut;
symlink/hardlink/path/inode replacement; stale generation or sequence gap.

Acceptance invalidates all A03 ordinary process/restart evidence and any R4/A06
vectors that consume this handoff. A03 will rerun the focused driver, native P,
process, fault, and independent-replay gates against the accepted source
commit/tree and interface digest.

### Required evidence (before acceptance)

```text
positive_vectors = exact non-empty Proposal body/evidence; clean restart lookup;
                   parent/context/epoch/validator-set/profile exact match
negative_mutants = body/metadata/index/hash/fingerprint/namespace/parent/profile
                   substitutions; malformed/truncated/oversize/duplicate bytes
fault_matrix = append/head lag; response loss; SIGKILL at append/publish/readback;
               path/inode replacement; stale generation/sequence gap
exact_commands = source-bound unit, process and replay commands with SHA-256
                 output from an authorized clean clone
independent_replay = required by A06 and a reviewer outside A02/A03; pending
```

## Review decision

```text
owner_decision = pending
independent_reviewer = pending
accepted_interface_version = pending
accepted_interface_digest = pending
source_commit = pending
source_tree = pending
notes = A03 must not edit A02-owned surfaces before acceptance
```
