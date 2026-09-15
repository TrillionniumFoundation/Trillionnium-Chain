# Candidate proposal-witness journal

**Separately anchored proposal-witness journal candidate.** The explicit Linux
`candidate-proposal-journal` feature in `trnm-consensus-signer-journal` supplies
`ProposalJournalV1` and `JournaledProposalProducerV1` for the existing
`ProposalSignatureProducerV0` port. This is not a Vote/Timeout signer, a new wire
statement, an epoch handoff or a SafetyRules capability. The composition first
obtains a complete valid preimage from the actual Ready Core/native owner; a
bare journal request does not prove parent ancestry or payload validity.

The commissioned profile binds the exact strict-Ed25519 validator set and
parameters, one author/key, signer-profile reference, opaque external watermark
scope and capacity. Production parameters, wrong context, semantic-mode anchors
and capacities outside 1..4096 requests reject. One profile/namespace is fixed to
one epoch; key rotation and general epoch transitions are not implemented by
opening a new local file. The opaque monotonic service is a trusted injected
boundary. The test file/memory anchors are not independent hardware evidence.

The local, non-wire format is big-endian and closed: a 104-byte `TRNMPJ01` header
contains magic[8], profile digest[32], random-instance journal ID[32] and header
checksum[32]. Every 257-byte event contains sequence[8], tag[1], exact
request[120], signature[64], predecessor checksum[32] and checksum[32]. Request
bytes are proposal ID[32], parent ID[32], epoch[8], view[8], height[8] and signing
root[32]; the profile supplies the exact author, key, set and signer context.
Tag 0 is Prepared with a zero signature; tag 1 is Signed with a strictly verified
signature and the identical request. Domain-separated checksums bind the full
record, profile and instance. There is no permissive decoding or legacy format
migration. Maximum encoded log size is 104 + 8192 * 257 = 2,105,448 bytes.

Admission freshly audits the complete bounded log, verifies every retained
signature and matches the independently read anchor. Exact already-signed replay
returns the stored bytes without custody. A different request at an existing
view, a lower new view, a new request while an intent is pending, or capacity
exhaustion rejects without log/anchor/custody mutation. Height is bound context,
not an additional cross-view ordering rule: valid fork choice remains Core's
responsibility. For a new intent, append Prepared, synchronize file and parent,
re-read the exact event and complete external CAS/readback **before** custody.
Verify the returned signature, re-audit, then durably append Signed and complete
its separate CAS/readback before returning any signature to the caller.

All uncertain append/sync/CAS/custody failures close the live readiness barrier.
`open_existing` requires exact source/target readback and permits only the exact
one-event local-head lag from its independently anchored predecessor; missing,
ahead, unrelated or more distant anchors reject without truncation. The existing
file is never reset. `recover_observed_signature` has no custody parameter: it
verifies already-observed bytes and completes only an anchored identical pending
request, or returns its exact signed replay. No signature can manufacture a new
intent. A retried custody operation can repeat the identical request only; it
cannot change the signed root. Publication-body recovery and the whole-node
archive/outbox remain separate obligations.

Linux descriptor/path checks require a canonical owner-controlled private
parent, same-owner regular single-link 0600 file, no-follow opens, one exclusive
file lock and the creating process identity. Observed parent/file replacement,
permissions or same-inode content change fail closed. Complete log auditing is
intentional and bounded; it is not scalable pruning or protection against an
unobserved rename/restore race, malicious trusted anchor, physical power loss or
an independently rolled-back entire machine. Error variants in
`ProposalJournalErrorV1` are local (not wire codes): InvalidProfile/InvalidRequest,
Conflict and Capacity grant no new signature; Corrupt/Namespace/Locked/Anchor
block opening or continued use. An invalid custody result closes readiness; an
invalid caller-provided observed signature rejects without altering the pending
intent. NotReady refuses further operation; Producer/Io after possible effects
require reopen and exact recovery. The adapter maps invalid/conflicting/capacity
requests to Rejected and uncertain authority/storage failures to Unavailable.

`src/proposal_journal_tests_v1.rs` exercises the actual port, strict signatures,
byte layout, no-resign replay, higher-view height rebasing, wrong context,
capacity, lost custody response, invalid signatures, content/endpoint changes,
rollback and missing anchors. Five subprocess-exit cuts cover Prepared sync,
Prepared anchor, custody-applied, Signed sync and Signed anchor; the external
file anchor in these cases remains a declared fixture. These regressions and
all feature-specific compilation must run on the reviewed source. Their local
results do not appoint an independent reviewer or enable production.
