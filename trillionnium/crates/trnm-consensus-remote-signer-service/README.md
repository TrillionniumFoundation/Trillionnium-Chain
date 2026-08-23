# Remote signer P0 service slice

This crate is a deliberately small, independently runnable vertical slice for
the Stage-1 remote-signer boundary. It accepts the existing
trnm-consensus-remote-signer-protocol schema-1 request bytes over a
length-prefixed Unix socket, validates the configured role/service/client
binding, and reserves the request in a separate SQLite namespace before
calling an Ed25519 key held by the signer process.

The reservation transaction is BEGIN IMMEDIATE with
PRAGMA synchronous=FULL. It advances a durable sequence using
UPDATE ... WHERE sequence = expected, records epoch, view, purpose, nonce,
and request fingerprint, and rejects:

- a duplicate nonce or request fingerprint;
- a second request for the same epoch/view/purpose;
- an epoch/view rollback;
- a non-increasing authorizing SafetyState revision for a new request;
- a purpose disabled by the process policy; and
- malformed or differently bound protocol bytes.

The SQLite namespace is immutable with respect to its configured binding:
opening a non-empty file with a different process generation or lease fails
before the Unix socket is published, and a file containing more than one
watermark scope is rejected before migration can insert another row. This is
local fail-stop validation, not an externally administered fencing authority.

The response is the existing exact protocol response envelope. The service
verifies the generated signature against the request signing root before
returning it; a future Node client must verify the response again before any
Core effect.

## Deliberate boundaries

This is not a consensus-runtime connection and does not claim SafetyRules
authority. It does not provide:

- Core/SafetyRules admission or locked-QC evaluation;
- a lease, process-generation, or checkpoint resolver;
- HSM/KMS key custody;
- an externally administered monotonic watermark or whole-node rollback
  protection (the SQLite namespace is local state);
- peer-credential/lease attestation beyond the Unix socket's 0600 same-UID
  filesystem permission;
- full crash/power-loss recovery proof: a matching pending reservation can be
  retried deterministically, but the slice does not persist/replay the final
  response or an append-only signature event;
- WAL/SHM identity pinning or protection from a trusted-filesystem operator
  replacing the local database between process starts; or
- proposal, handoff, P2P, or operator-purpose signing.

Accordingly, the crate metadata and exported truth constants keep
runtime_activation, production_signature_producer,
consensus_runtime_integration, and production_activation false. The
metadata also marks SafetyRules evaluation, safe-vote authority, and a
signature-event journal as false. The
deterministic fixture executable is test tooling, not a deployment format. It
embeds a deterministic test-only Ed25519 seed and must not be used as a
validator credential source.

## Local checks

    cargo test -p trnm-consensus-remote-signer-service
    python3 scripts/remote_signer_p0_test.py

The Python test launches trnm-remote-signer-p0 serve-fixture, sends real
schema-1 request bytes through the Unix socket, checks success/rejection
frames, restarts the process with the same watermark path, and checks that a
lower round remains rejected.

The Rust OS-process test additionally SIGKILLs the owner and starts candidates
with altered generation and lease bindings; both fail before publishing a
socket. It does not turn the local SQLite file into a trusted anti-rollback
authority; an external append-only CAS/HSM boundary remains required.
