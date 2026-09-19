# M04 P2P / Session / Dissemination technical specification v1

Status: **implementation contract; candidate only**

## Authority

M04 owns authenticated ingress, peer sessions, durable replay admission,
bounded dissemination and transport lifecycle. M02 owns consensus validity;
M05 owns transaction admission; M13 owns checkpoint/state-sync verification.
A transport ACK never means a vote, committed block or finalized transaction.
Overload is a local availability result and cannot make a block invalid.

The selected implementation target below is `dev-p2p-tls-v1`: a proposed
private-devnet profile, not a frozen v0 wire change or a deployed listener.
Its limits enter an operator-signed devnet descriptor shared by all peers.
Production activation requires a separately reviewed network profile.

### Source map and implementation boundary

| Source | Implemented responsibility | Remaining integration |
|---|---|---|
| `trillionnium/crates/trnm-poco-node-io/src/authenticated_p2p.rs` | `PeerSessionIdentityV0`, exact-next nonce, one pending frame, typed verification token | No socket, TLS, discovery or persistent backend |
| `trillionnium/crates/trnm-poco-node/src/p2p_session_ingress.rs` | Candidate Ed25519 handshake/frame ingress, nested Vote/TimeoutVote/QC/TC verification, fsynced session and authenticated-frame replay anchor, child-process restart/tamper checks | No listener, TLS identity administration, Core ACK atomicity or external anti-rollback |
| `trillionnium/crates/trnm-poco-node-host/src/persistent_p2p_ingress_bridge.rs` | Candidate bridge to prepared Core ingress and ACK | Connect an independently authenticated listener |
| `trillionnium/crates/trnm-poco-lab-validator/src/p2p_admission.rs` | Candidate peer-admission integration | Multi-host production authentication |
| `trillionnium/crates/trnm-consensus-peer-lease/src/lib.rs` | Unix lease transport, append-only chain, cross-process fencing | Not consensus payload transport or host attestation |

The existing admission frame has a 4 MiB **payload** maximum. Unix credentials
and local test keys do not establish cross-host validator identity. New ports
below are planned adapters; their names do not claim current implementation.

## Interfaces

`OpenSessionV1` produces two directional session identities plus a lane map.
`AdmitDataV1` converts transport DATA into `AuthenticatedPeerFrameV0`, verifies
it through `PeerFrameSourceV0`, and obtains `VerifiedPeerFrameV0` before admission.
`RecoverIngressV1` obtains durable replay state through
`PeerReplayRecoverySourceV0`; callers cannot construct a trusted recovered state.
`DisseminateV1(object_id, kind, audience, canonical_bytes, expiry_height)` queues
an immutable object. `AcknowledgePreparedV1` consumes the exact host-prepared
receipt; it is not callable with an arbitrary nonce or digest.

### Selected transport and identity handshake

1. Use TLS 1.3 over TCP with ALPN `trnm-dev-p2p/1`; disable TLS early data,
   application compression, renegotiation and unauthenticated fallback.
2. Require certificates on both sides. The signed devnet descriptor maps the
   SHA-256 of certificate SPKI to a unique `peer_id`, validator identity, allowed
   roles and chain/profile. Possession of any CA-signed certificate is insufficient.
3. Reject unknown, revoked, expired or wrong-role keys before allocating a
   consensus session. Certificate time validation is transport-local; it never
   changes M02 validity. Key rotation requires a new descriptor generation and
   reconnect; it cannot rebind an existing session.
4. Each direction sends one bounded HELLO within 5 s after TLS establishment.
   HELLO fields in order are magic `TRNMHLO1` (8 bytes), version `u16=1`, role
   `u8` (1 validator, 2 observer), peer ID, chain ID, genesis digest, protocol
   digest, profile digest (five 32-byte values), persistent local generation
   `u64`, random challenge (32 bytes), maximum DATA payload `u32`.
5. Integers are big-endian. The HELLO is exactly 215 bytes; reject trailing data,
   zero identities, zero generation, wrong chain/genesis/protocol/profile or
   an advertised limit different from the signed descriptor. No optional fields.
6. Bind both HELLO byte strings, initiator/responder order and 32 TLS exporter
   bytes using label `EXPORTER-trnm-dev-p2p-v1`. The base session digest is
   SHA-256 of `trnm.dev.p2p.session.v1\0 || initiator_hello || responder_hello || exporter`.
7. Derive a separate 32-byte session ID per direction/lane using SHA-256 of
   `trnm.dev.p2p.lane.v1\0 || base_session || direction_u8 || lane_u8`.
   Direction 0 is initiator to responder. Each side verifies the peer certificate
   mapping against the peer ID in HELLO. TLS Finished authenticates the exporter.
8. Persist the new generation and both session bindings before READY. A failed
   persist closes the connection; no inbound DATA reaches a module.

Generation allocation uses checked `previous+1` in the sender's durable store.
The receiver records the highest authenticated generation per peer; a smaller
or equal generation on a newly negotiated connection is rejected. Reconnecting
never deletes a pending older-session ingress record: recovery first resolves
its prepared Core receipt, then fences it from new DATA. Rotation cannot erase
an uncertain delivery. A coherent rollback of both stores needs the external
lease/watermark authority; a hash chain alone is not that authority.

### Frame layout and routing

All application frames use this 96-byte header followed by exactly `payload_len`
bytes. These are dev transport bytes, never consensus signing preimages.

| Offset | Field | Size / rule |
|---|---|---|
| 0 | magic | 8 bytes `TRNMP2P1` |
| 8 | transport version | big-endian `u16=1` |
| 10 | frame kind | `u8`: 1 DATA, 2 ACK, 3 CLOSE |
| 11 | lane | `u8`: 0 votes/timeouts/certificates, 1 transactions, 2 sync/artifact, 3 proposals |
| 12 | directional lane session ID | 32 bytes |
| 44 | sender generation | `u64` |
| 52 | replay nonce | `u64`, positive for DATA/ACK, zero for CLOSE |
| 60 | payload length | `u32`, checked before allocation |
| 64 | payload digest | 32 bytes |

Every frame's payload digest is SHA-256 of
`trnm.dev.p2p.payload.v1\0 || payload_len_u32 || payload_bytes`.
DATA payload is a `u16` message-kind tag followed by the exact M00 canonical
object. ACK length must be exactly 64 and CLOSE length exactly 2 before allocation.
Planned dev message tags are 1 vote, 2 timeout, 3 proposal, 4 certificate,
5 transaction, 6 checkpoint request, 7 checkpoint response, 8 state chunk.
Tags 1/2/4 use lane 0, tag 5 lane 1, tags 6-8 lane 2, tag 3 lane 3. Roles and the signed profile
further restrict message kinds. Unknown tags or noncanonical objects are rejected.
Existing frozen object bytes/domains remain unchanged inside the envelope.

ACK payload is the acknowledged DATA digest plus a 32-byte durable prepared
receipt digest (64 bytes). Its header echoes the DATA nonce, DATA-sender generation and lane session;
ACKs do not consume a DATA nonce and never receive ACKs. CLOSE payload is a
`u16` reason only: zero for orderly shutdown, otherwise 1..11 in the error-code
order below. CLOSE uses the sender's lane-0 session and generation with nonce zero
and closes the connection; unknown reasons are `BAD_FRAME`.
TLS authenticates ACK/CLOSE; a valid ACK must additionally
match the sender's exact retained outbound intent. No zero-data DATA is legal.

## State machine

```text
Disconnected -> TLSAuthenticated -> HelloBound -> ReplayRecovered -> Active
Active -> Draining -> Closed
any state -> Quarantined   (identity, persistence or replay contradiction)
```

### DATA admission and ACK algorithm

1. Read only the header; validate magic, version, connection-bound identity,
   lane and length. Reserve peer/global byte and work credits before reading body.
2. Read the bounded body before its deadline; hash exact bytes, validate the
   canonical object and role/message-kind pair. Hash failure closes this session.
3. Check the lane's exact-next nonce. One pending DATA is allowed per direction
   per lane, matching current `CandidateP2pAdmissionV0` semantics. A nonce gap is
   `NON_CONTIGUOUS`; an altered retry is `CONFLICTING_REPLAY`. No unbounded gap buffer.
4. Persist the payload, authenticated session tuple, nonce and digest together
   with the replay intent before exposing it to the host. A metadata-only replay
   record is insufficient because restart must recover the exact body.
5. Present the verified token to the correct consumer. The host's durable
   prepared receipt must bind this payload and predecessor. Only then advance
   the durable ACK floor and send ACK. Consumer acceptance is not finality.
6. Free credits only when ownership transfers to a bounded consumer or the
   request is rejected. On uncertain I/O, poison the owner and recover before retry.

A same-pending exact retry resumes the existing intent; a previously ACKed exact
retry returns the retained receipt if available, never executes again. Older
DATA without retained receipt is `STALE_NONCE`, not a newly accepted request.
ACK loss retains the outbound intent until durable peer readback/retransmission
resolves it. Nonce exhaustion closes the lane and requires a new generation.

Lane 0 is scheduled before proposal lane 3, then lane 1/2, with deficit
round-robin across peers within each lane. Reserve independent worker/byte
credits for lane 0 and lane 3; transaction/sync work cannot consume them.
ACK/CLOSE processing uses a separate bounded control queue and no DATA credit.
A slow proposal or state chunk therefore cannot occupy the only outstanding
vote lane or block its ACK. Workers enforce per-object work bounds; a single
large certificate cannot monopolize the reserved control worker indefinitely.

## Persistence and recovery

Each directional lane journal binds chain/genesis, protocol/profile, peer key,
session/generation, retained payload, pending nonce, highest acknowledged nonce,
prepared receipt and previous record digest. Use descriptor-pinned namespaces,
exclusive ownership and complete CAS transitions; copied paths do not confer authority.
Startup validates the entire required journal chain and body digests before opening
the lane. A one-record discrepancy is repaired only if the existing storage
contract proves the exact source/target pair; never reset the replay floor.

Crashes before payload persistence permit resend; crashes after prepared Core
acceptance require that exact receipt readback; crashes after ACK durability
return the original ACK. Missing payloads, replaced namespace, rollback anchor
mismatch or conflicting receipt quarantine the peer lane and preserve evidence.
Session journal GC requires all pending DATA resolved and a durable successor
fence; object bytes follow the owning consumer's retention contract. M04 must
not invent a finalized-height shortcut for unresolved ingress.

## Resource bounds

The following are **proposed signed private-devnet defaults**, not measured
capacity or consensus parameters. Startup rejects zero, overflow or incompatible
limits; changing the wire/profile limits requires a new profile digest.

| Resource | Dev default / hard handling |
|---|---|
| Authenticated peers | 32 global, one connection per peer; deterministic duplicate winner is lower base-session digest |
| Incomplete TLS/HELLO | 8 global, 2 per source IP; 64 KiB TLS-handshake budget, 5 s deadline |
| DATA payload | 4 MiB max; transactions additionally obey M05's smaller envelope limits |
| Pending DATA | 1 per direction/lane/peer; 128 global inbound slots |
| Inbound retained payload memory | 32 MiB lane 0, 16 MiB each lane 1/2/3; spill only to bounded durable store |
| Outbound queued bytes | 8 MiB per peer, 128 MiB global; return `OVER_BUDGET`, never silently discard durable intents |
| Auth verification workers | 4 total, at least 1 reserved lane 0; each queue 64 items |
| Read/write deadline | 5 s header, 15 s complete DATA, 15 s stalled writer; reconnect with capped backoff |
| Retries | 250 ms initial, double to 5 s, jitter; 8 attempts then disconnect and retain unresolved intent |
| ACK/control queue | 64 frames/peer, 4096 global, each <=160 bytes |
| Durable replay storage | 1 GiB/node initially; capacity exhaustion stops new DATA, keeps recovery/readback available |

Handshake rejection sends at most one bounded error after authentication.
Before authentication close silently. Per-IP throttling is only admission
protection; identity quotas also apply so one authenticated peer cannot multiply
capacity by reconnecting. No automatic decompression is supported in this profile.

## Security

Wire error codes are `BAD_FRAME`, `WRONG_DOMAIN`, `UNAUTHORIZED_ROLE`,
`STALE_NONCE`, `NON_CONTIGUOUS`, `CONFLICTING_REPLAY`, `OVER_BUDGET`,
`PEER_BUSY`, `RECOVERY_REQUIRED`, `IO_UNCERTAIN` and `UNSUPPORTED_PROFILE`.
Malformed/domain/authentication errors close the connection; overload keeps it
open only if it can drain without extra allocation. Persistence contradictions
quarantine the affected owner. Errors expose no certificate private material,
local paths or payload contents. Advisory peer scores never override validity.

Discovery in this dev profile is the signed static peer list only. No public
DHT, relaying to arbitrary URLs, NAT traversal or validator membership mutation
is implied. Transport credentials are distinct from consensus signing keys.

## Observability and SLO

Record handshake/admission/ACK latency, per-lane credits, pending age, good bytes,
rejected bytes, duplicate rate, reconnects, fsync latency and quarantine reasons.
Use fixed peer-role/lane/reason labels; peer IDs belong in bounded diagnostic
records, not unbounded metric labels. Report p50/p95/p99 and dropped samples.
The `bounded-io-runtime-v1` SLO target is a test input; it is not evidence of
subsecond finality. M17 measures the full finality path independently.
One outstanding DATA per lane limits that lane to at most one acknowledged
frame per ACK round trip; report this cap rather than claiming unmeasured WAN
throughput. Windowed DATA needs a separately specified replay/admission version.

## Verification and evidence

| Campaign | Positive case | Required rejection/fault |
|---|---|---|
| Handshake | Two independently implemented TLS clients agree on lane IDs | Wrong certificate peer/chain/profile, expired key, early data, duplicate generation |
| Parser | Fragmented header/body and exact maximum frame round-trip | Every truncation, length overflow, trailing bytes, unknown tag, digest mismatch |
| Replay | Exact retry before/after ACK and restart yields one Core admission | Changed body at same nonce, stale token, nonce gap, overflow |
| Durability | Kill at payload write/sync, prepared receipt, ACK-floor sync and ACK loss | Missing body, rolled-back journal, substituted directory, fsync uncertainty |
| Scheduling | Slow sync lane while votes and ACKs continue | Fill lane 2, exhaust peer credits, slow reader, repeated reconnect |
| Network | 4/7 independent processes at 20/80/180 ms RTT | 0/1/5% loss, duplicates, partition/heal and certificate rotation |

Producer/consumer review binds M00 codecs, M02 prepared ingress, M05 transaction
handoff, M08 durable recovery and M13 sync input to the same source/profile.
Run current crate tests as regression input; new TLS/frame tests are planned
until the listener exists. A loopback or Unix-only test cannot close multi-host
identity qualification.

## Activation boundary

Production reachability requires the authenticated persistent listener, exact
payload-to-Core ACK recovery, anti-replay authority across machines, bounded
fault campaigns and independent security review. The proposed dev profile can
be built without granting production signing, release or public-testnet status.
