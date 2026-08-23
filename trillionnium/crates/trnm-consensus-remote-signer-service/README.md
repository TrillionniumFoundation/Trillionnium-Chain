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

## External authority seam

`ExternalAuthorityAdapterV1` and
`RemoteSignerService::external_authority_request_v1` define the facts and
ordering for the bounded timeout bridge. The
`process_request_with_external_authority_v1` entry point now performs durable
response replay, cross-process semantic compare-and-advance, fixture-key
access only after the reservation, and durable response binding before local
completion. It never falls back to the local SQLite path. Vote requests remain
fail-closed because this slice does not provide Core/SafetyRules authority.

The bridge uses the independent
`trnm-consensus-external-watermark` process and its semantic sidecar to persist
epoch/view/Safety-revision ordering. Its append-only response journal binds the
exact request facts and signature across restart and rejects ambiguous
reservation/response state. The external-watermark black-box tests and the
remote-signer OS-process integration test provide the crash, restart, replay,
and tamper evidence for this narrow path.

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
- a production HSM/KMS or whole-node rollback authority; the external
  watermark process is a tested local boundary, not host attestation or an
  operator-independent anti-rollback service;
- peer-credential/lease attestation beyond the Unix socket's 0600 same-UID
  filesystem permission;
- full Core crash/power-loss recovery proof: this slice persists and replays
  timeout responses, but it is not connected to block/QC/finality commit or a
  production signature-event journal;
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

    cargo test --locked -p trnm-consensus-remote-signer-service
    cargo test --locked -p trnm-consensus-remote-signer-service --test external_authority_adapter
    python3 scripts/remote_signer_p0_test.py

The Python test launches trnm-remote-signer-p0 serve-fixture, sends real
schema-1 request bytes through the Unix socket, checks success/rejection
frames, restarts the process with the same watermark path, and checks that a
lower round remains rejected.

The Rust OS-process test additionally SIGKILLs the owner and starts candidates
with altered generation and lease bindings; both fail before publishing a
socket. It does not turn the local SQLite file into a trusted anti-rollback
authority; an external append-only CAS/HSM boundary remains required.
