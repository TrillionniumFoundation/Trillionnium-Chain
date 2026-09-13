# `trnm-poco-da-v1`

Candidate-only local deterministic storage/kernel for the PoCO AI-native v1
`TransactionBatch` DA namespace.

The crate closes one bounded implementation tranche: typed context/namespace/
object/batch/chunk identifiers, exact author sequencing, per-author and global
queue quotas, durable bytes/manifest/capacity reservation before an attestation
intent can escape, strict Ed25519 attestations, checked weighted certificate
quorum, local retrieval and repair, monotonic retention obligations, durable
GC tombstones, and objective attestor-equivocation evidence.

A follow-on candidate adds transport-independent signed **full-range**
retrieval requests and committee-member receipts. Every returned chunk carries
a canonical inclusion path to the certified chunk root; verification rebuilds
the exact transaction batch and yields a private, non-copyable carrier bound
to the target scope/store/config and certificate. That carrier can repair only
an already-latched unavailable row, through the immutable durable manifest,
followed by a fresh complete-byte and certificate readback. Verification
independently rebinds the certificate author key to the committed policy and
uses the narrower repair window. Consumption rechecks that its explicit repair
height has not moved backward or beyond the carrier's freshness bound.

Journal schema v2 allocates attestations from a checksummed persistent
high-watermark rather than SQLite `rowid`; deleting a journal row, reusing a
sequence, or modifying the watermark fails closed. The signed attestation body
binds an immutable durable-manifest checksum (envelope, author, exact bytes,
chunks, identity, and committed configuration), so later certificate,
retention, repair-revision, or availability-state changes cannot invalidate or
silently retarget an escaped signature.

This is a local journal guarantee, not protection against rollback of the
entire store plus its metadata. `anti_whole_store_rollback_authority=false`
remains explicit until the whole-node checkpoint/CAS tranche is integrated.

The SQLite store opens a fresh connection for every operation and confirms
every successful transition through a fresh read. Exact replay is idempotent;
conflicts, rollback, row/checksum tampering, schema drift, commit-third-state,
early GC, alternate repair bytes, duplicate signer weight, and quota overflow
fail closed.

This is **not** the complete document-06 protocol implementation. In
particular it:

- supports only `TransactionBatch`; `ArtifactEvidence` is rejected;
- treats transaction entries as bounded exact bytes and does not yet contain
  the complete independent `AgentTransactionV1` CEV1 parser;
- uses a closed candidate CEV1-compatible subset for the listed records, not a
  repository-wide normative wire freeze;
- has no network, peer authentication, compression, erasure coding, sampling,
  funding/accounting, state-sync, Order vote eligibility, Node, Safety,
  signer, or whole-node-checkpoint authority;
- implements neither arbitrary chunk ranges nor a requester registry, durable
  responder-signing journal, proof-of-non-response/withholding adjudication, or
  peer routing; the requester key is an explicit out-of-band trust pin, and the
  repair height is not authoritative until a later Node owner supplies it;
- exposes no constructor for `FinalizedGcPermitV1`; the only issuer is compiled
  under `cfg(test)`, so downstream/production code cannot reach byte deletion
  until a later finalized chain-checkpoint/CAS owner is integrated;
- does not make non-response slashable evidence; and
- is not protocol activation, global v1 implementation, interoperability, or
  production evidence.

The checked schema/vector and boundary gate are therefore candidate evidence
only. All global G2, implementation, freeze, activation, and release flags
remain false.
