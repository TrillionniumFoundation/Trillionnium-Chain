# Native replay boundaries

`replay.hepta` implements the pure replay-state checks and successor-state
calculations from [`trnm-transport`](../../../trillionnium/crates/trnm-transport/src/lib.rs).
The HIA source compiles to native machine code through the pinned self-hosted
compiler. The same test vectors also execute through the upstream direct
machine emitter.

The function returns structural and state-transition facts. It does not mint a
`VerifiedPeerFrameV0`, accept a caller-supplied authentication flag, call
`PeerFrameSourceV0` or `PeerReplayRecoverySourceV0`, or persist a transition.
Those source-authority and storage owners still belong to the existing Node.
In particular, a successful pending proposal must pass the real frame-source
verification and owner prestate check before a future integrated owner can
publish it. A successful recovery check authenticates no database history.

## Entry and request format

The exported entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. The first buffer is
an immutable request; the second must have exactly 400 bytes and receives one
canonical state on success. The third is unused scratch and remains unchanged.
Every rejection preserves both mutable buffers byte-for-byte.

`TRP1` is a new in-process migration-test encoding. It is not an existing peer
wire format or durable schema, and changes no signed domain. All integer fields
below use little-endian unsigned encoding.

| Request offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `TRP1` |
| 4 | 1 | Version `1` |
| 5 | 1 | Operation `0` through `4` |
| 6 | 2 | Zero reserved bytes |
| 8 | 400 | Current replay state |
| 408 | Varies | No argument, one 216-byte frame, or one 400-byte expected prior |

| Operation | Exact request bytes | Success output |
| --- | ---: | --- |
| `0` recovery structure | 408 | The validated canonical input state |
| `1` frame precheck | 624 | Unchanged state after the original boundary checks |
| `2` acknowledge | 624 | Exact pending frame acknowledged and pending cleared |
| `3` pending proposal | 624 | Proposed pending state; exact pending replay is idempotent |
| `4` compare expected prior | 808 | Unchanged state when the complete expected prior matches |

Operation `4` compares two states. It does not create or consume a verified
token; token origin and ownership are still obligations of the caller's real
source-authority owner.

## Canonical value layouts

A session is 168 bytes: chain digest, protocol digest, peer digest, session
digest and profile digest, each 32 bytes, followed by an eight-byte generation.
Every digest must contain at least one nonzero byte; generation must be positive.

A frame is 216 bytes: session at offset `0`, eight-byte positive nonce at `168`,
nonzero 32-byte payload digest at `176`, and eight-byte payload length at `208`.
Payload length must be in `1..=2_097_152`.

| State offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 168 | Session |
| 168 | 8 | Highest acknowledged nonce |
| 176 | 8 | Pending tag: exactly `0` or `1` |
| 184 | 216 | Pending frame for tag `1`; all zero bytes for tag `0` |

The all-zero absent-pending area removes multiple encodings of the same state.
A present pending frame must have the same complete session and nonce exactly
`highest_acknowledged_nonce + 1`, with checked unsigned overflow.

With no pending frame, acknowledged nonce `u64::MAX` is a valid terminal state;
any next frame precheck returns replay overflow. With a pending frame, recovery
checks overflow before testing pending session/nonce equality, matching the
original constructor for valid typed frame values.

Frame prechecks preserve the original order: complete session mismatch first;
then exact pending replay, same-nonce conflicting replay, or another pending
frame; otherwise checked successor, stale nonce, then nonce gap. An exact
pending replay still requires a real source verification before adoption.
Acknowledgement checks equality of the entire pending frame, including payload
length, and advances no other session or nonce. State and frame constructors
run before these typed operation checks, as they do when decoding Rust values.

## Return codes

| Value | Meaning |
| ---: | --- |
| 0 | Requested pure check or successor calculation succeeded |
| 1 | Zero identity or payload digest |
| 2 | Zero session generation |
| 3 | Invalid frame nonce or payload length |
| 4 | Inconsistent recovered pending state |
| 5 | Replay nonce overflow |
| 6 | Wrong complete session |
| 7 | Stale nonce |
| 8 | Noncontiguous nonce |
| 9 | Another frame is pending |
| 10 | Conflicting replay at the pending nonce |
| 11 | Expected prior differs from current state |
| 12 | Acknowledgement does not equal the pending frame |
| 13 | Wrong request/output extent |
| 14 | Wrong magic, version, reserved bytes or operation |
| 15 | Noncanonical pending tag or absent-pending bytes |

The last three are encoding errors specific to `TRP1`. The other nonzero codes
retain the corresponding original `PeerAdmissionErrorV0` meaning; code `11`
reports only the prior-state comparison used by the original stale-token guard.

## Verification and remaining integration

`hia/tests/test_replay.py` executes native functions in disposable processes.
It checks both machine-code compiler paths, canonical recovery, response-loss
replay, proposal/ack sequences, full session/frame equality, unsigned limits,
rejection priority, every output's bytes and a deterministic state matrix.
Native output is also passed into a fresh process for recovery and ACK.
These are contract-vector and cross-compiler checks; they do not claim an
executed Rust-reference comparison or durable restart acceptance.

The Node's SQLite immediate transactions, audit-history continuity, payload
hash verification, response cache, exact outbox wire checks, permission/revoke
owner and crash recovery remain outside this module. The existing Rust crate
and owner cannot be removed based on these pure-kernel results.
