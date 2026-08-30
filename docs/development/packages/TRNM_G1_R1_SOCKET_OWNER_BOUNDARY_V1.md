# TRNM G1-R1 process-bound recovery owner socket boundary v1

Package ID: `trnm-g1-r1-payload-replay-recovery-owner-socket-v1`

Status: **candidate-only engineering boundary; not a G1 exit, production
authority, or real-device evidence**

Code-closure source for this continuation:

```text
branch = feature/chain-g1-external-blocker-closure-20260830
commit = c0e309743f9696c8ee8bc035ff4c427df4d0eb25
tree = 3b46b2e72879afb4750aab61ebab955ef2c375d1
base = 1663abd8935be4e5819f5ff0c7ded250a3664097
socket-hardening = 0049ff9c1
```

This package adds a narrow, externally callable process boundary around the
existing payload-replay recovery owner.  It is intentionally subordinate to
the [payload replay recovery and Core acknowledgement package](TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md)
and the canonical Chain plan.

## Contract

The owner binary is `trnm-payload-replay-recovery-owner-v1`.  Its startup
arguments bind one absolute payload WAL, acknowledgement root, namespace and
complete target record.  Those values are never accepted from a socket
request.  The process opens the exact owner and holds its payload and
acknowledgement locks for the lifetime of the listener.

The socket schema is:

```text
trnm.payload-replay-recovery-owner-socket.v1
```

Requests use a bounded, big-endian `TRRQ` frame and responses use a bounded
`TRRS` frame.  The only operations are:

```text
1 = status       -> strict canonical recovery projection
2 = recover      -> exact bounded one-record recovery, if safe
3 = acknowledge  -> explicit payload revision + acknowledgement digest
```

The status response carries a 32-byte endpoint identity and a canonical
projection decoded with `PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes`.
The endpoint identity includes the bound owner identity, socket device/inode
metadata and a fresh process nonce.  Clients can pin that identity and fail
closed if a daemon is replaced, even when a socket inode is reused.

On Linux the daemon authenticates the peer's effective UID with Unix peer
credentials.  On other Unix platforms the candidate boundary relies on the
private parent directory and mode `0600`; a platform-specific MAC is not
claimed.  Socket, parent-directory and owner identities are rechecked around
each request, and all I/O uses an absolute deadline.

### Per-connection failure isolation

The listener is deliberately sequential (`max_concurrent_connections=1`) and
keeps the existing five-second absolute operation deadline for each accepted
stream.  Authentication, frame parsing, and response writes carry explicit
client-transport provenance.  A client that authenticates to the socket but
is not on the UID allowlist, closes at EOF, sends a truncated/invalid frame,
times out while dribbling bytes, or resets/breaks the pipe while a response is
written is discarded as a non-fatal connection failure; it cannot terminate
the owner daemon.  Failure of the local peer-credential lookup, owner-side
identity/path changes, WAL or acknowledgement corruption, and other
fail-closed authority invariants remain fatal even when that client disconnects
before receiving the error response.  The source marker
`payload_replay_recovery_socket_client_transport_errors_non_fatal=true` and
the focused process regression lock this distinction without changing any
production activation flag.

Acknowledgement is deliberately an explicit, caller-supplied Core fact.  The
socket returns the immutable ledger receipt and exposes the existing truth:

```text
atomic_with_core=false
production=false
candidate_only=true
```

## Safety and non-claims

The daemon never deletes an existing socket path, creates a missing WAL, or
silently chooses between a divergent WAL and head.  Cleanup after a graceful
exit is fenced by socket device/inode/owner/mode/link-count identity; an
operator must remove a stale path left by a hard kill after verifying its
ownership.

This boundary does **not** provide a cryptographic message MAC, host
attestation, private-key/HSM authority, whole-node anti-rollback, Core
`SafetyState` atomicity, replay-to-Core execution, multi-block/finality
integration, or production validator activation.  The crate and central
metadata therefore keep production candidate and consensus activation false.

## Verification

The focused package gate covers formatting, unit tests, client-transport error
classification, the daemon-survives-malformed-client regression, the socket
restart and identity-pin integration test, clippy with `-D warnings`,
source/manifest truth checks, and the existing recovery workflow policy.  The
integration test exercises status, identity pinning, explicit synthetic
acknowledgement and idempotent replay across a daemon replacement; it does not
represent a real Core acknowledgement or real-device campaign.

The companion G1 process-host fixture normalizes its temporary root to mode
0700 because the production admission owner rejects group/world-writable
parents.  This is a test-fixture correction, not a relaxation of the path
identity fence.  The process-host generation successor and three-block proof
horizon are checked before any WAL handoff.

Remaining external blockers include real Core-owned acknowledgement wiring,
authenticated node-to-owner deployment, MAC/host identity policy, crash and
anti-rollback evidence on the target machine, and the broader G1 native-host
and consensus exit gates.
