# DA-FULLREP-V1 candidate contract

Status: **candidate-non-normative; globally disabled**.

## Namespaces

- `transaction-batch`: ordered canonical transaction bytes.
- `artifact-evidence`: model/input/output/checkpoint/proof evidence bytes.

The namespace participates in every ID, request, response, certificate, repair and retention statement. Cross-namespace substitution fails closed.

## Provider transition

```text
Absent
 -> BytesWritten
 -> ManifestDurable
 -> JournalDurable
 -> FreshReadback
 -> AttestationReleased
```

Only the last transition releases an attestation. A threshold certificate is built from sorted unique providers over one exact `(namespace, object_id, content_digest, length, retention_until, committee_hash)` statement.

## Retrieval and repair

The baseline requires complete bytes. A requester verifies identity, namespace, full length and digest. Repair accepts a source only after complete verification and creates the same durable-before-attest chain on the repaired provider.

## Withholding

A certified provider that fails or refuses an authenticated complete retrieval request during the promised window can produce `WithholdingEvidenceV1`. Lack of one response is evidence under the frozen timeout/fault contract, not automatic slash authority.

## Retention and GC

Expiry alone is insufficient. Task, challenge, settlement, state-sync and audit holds must all be closed. A Node-owned finality/checkpoint permit is required. This candidate package exposes no production permit issuer.

## Mode rejection

Any certificate claiming erasure coding, sampling, partial-range availability or `DA-DAS-V1` is rejected while the full-replication profile is active.
