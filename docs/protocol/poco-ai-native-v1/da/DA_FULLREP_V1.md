# DA-FULLREP-V1 candidate contract

Status: **candidate-non-normative; globally disabled**.

`DA-FULLREP-V1` is the launch-baseline profile for complete replication.  It
is not `DA-DAS-V1`: erasure coding, sampling-only certificates, and partial
availability claims are rejected until a separately versioned profile is
frozen and independently reproduced.

## Namespaces and object identity

- `transaction-batch`: ordered canonical transaction bytes;
- `artifact-evidence`: model/input/output/checkpoint/proof evidence bytes.

The namespace, complete byte length, and content digest participate in every
object ID, manifest, request, response, certificate, repair and retention
statement.  A transaction-batch ID cannot be looked up in the artifact-evidence
namespace, and vice versa.

## Durable provider transition

```text
Absent -> BytesWritten -> ManifestDurable -> JournalDurable
       -> FreshReadback -> AttestationReleased
```

An attestation is fail-closed until the exact bytes and immutable manifest are
durable and a fresh readback recomputes the same digest/length.  Replaying a
different byte string, namespace, retention window, or manifest checksum under
one object ID is rejected.  A certificate is a threshold statement about
durable replicas; it does not prove correctness, privacy, result validity,
payment, or perpetual availability.

## Authenticated complete retrieval

The candidate request/response envelope binds:

```text
peer identity, namespace, BatchRef/object ID, first byte, complete byte count,
request nonce, request height, expiry height, response digest and responder
identity
```

The A11 independent model uses a deterministic keyed tag solely to exercise
binding and fail-closed behavior.  It is not a production Ed25519 signer,
requester registry, peer-routing service, quota authority, or Order proof.
The local Rust candidate exposes the corresponding signed full-range proof
types; generic ranges remain rejected by this full-replication profile unless
the exact complete range is requested.

An expired request, unauthenticated envelope, wrong namespace, stale
certificate, quota overflow, or partial range (`incomplete-range`) must reject
before bytes are returned.  The responder must be both an active committee
member and an attestor named by the exact certificate; committee membership
alone is insufficient.  Receipt/body identifiers and the returned-chunk root
are recomputed before the complete digest-matching value is released.

## Repair, withholding and retention

Repair accepts only complete bytes whose namespace, object ID and digest match
the certified statement.  A missing source or inconsistent source cannot create
a repaired attestation.  A withholding witness names a provider that is
actually in the active certificate and records the request nonce/window; a
timeout witness is evidence under the declared fault contract, not automatic
slashing or finality authority.

Task, challenge, settlement, state-sync and audit holds all block deletion.
Expiry alone is insufficient.  GC requires an explicit Node-owned finalized
checkpoint/anti-rollback permit.  The candidate model accepts a strict boolean
test permit only to exercise the boundary and has no production permit issuer.

## Candidate boundary

This contract does not supply authenticated production P2P, durable requester
or responder signer journals, canonical ArtifactEvidence integration (the
separate `artifact-evidence` namespace remains explicitly typed and rejected
by this transaction-batch-only crate), accepted `BatchRef`/Order
retrieval-before-vote binding, whole-node CAS, Node reachability,
multi-host fault evidence, production GC, or global G2 authority.  All of those
remain false in machine truth.  `DA-DAS-V1` remains disabled and cannot be used
as a fallback when full-range retrieval fails.
