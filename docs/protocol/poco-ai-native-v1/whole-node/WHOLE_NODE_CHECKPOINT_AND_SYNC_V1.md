# Whole-node checkpoint, anti-rollback and state-sync v1 candidate

Status: **candidate-non-normative; no production authority**.

## Exact snapshot

A whole-node candidate snapshot contains exactly one freshly authenticated head from:

```text
DA
Agent/Market
Execution/MVCC
Verify/Challenge
Settlement
```

Each head binds store ID, monotonic sequence, finalized Order height/block, state root, journal root and file identity. All heads must name the same Order cut. The application root is derived from the complete ordered projection and must equal the finalized Order proof's `post_state_root`.

A local composite root that is not committed by Order is not an application root.

## Checkpoint transition

```text
ExactSourceSnapshot
 -> PreparedCheckpoint(predecessor)
 -> LocalTargetDurable
 -> ExternalAnchorCAS
 -> FreshLocalAndExternalReadback
 -> Ready
```

The external anchor stores at least chain identity, generation and checkpoint hash outside the rollbackable database namespace. It advances only by exact successor CAS.

Response loss resolves as follows:

- exact predecessor plus exact already-committed target: return the same checkpoint;
- exact predecessor plus a different target: reject;
- local prefix behind external anchor: reject as rollback;
- local target ahead of external anchor: ambiguous, fail closed;
- checksum, namespace, manifest or file inventory drift: reject.

A path hash or database checksum alone is not anti-rollback authority.

## State sync

State sync receives a finalized source trust checkpoint, target Order proof, target application root, chunk list and exact chunk hashes. Chunks install into a staging namespace. The implementation recomputes the target root and verifies all live legal/DA/retention obligations before an atomic swap. It never imports or lowers Safety, signer, attestation or external-anchor state.

## Hard prohibition

No operation may sign, vote, broadcast, settle, delete DA bytes or expose a synced store before exact checkpoint and external-anchor verification.
