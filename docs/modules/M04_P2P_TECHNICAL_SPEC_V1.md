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
| `trillionnium/crates/trnm-poco-node/src/p2p_session_ingress.rs` | Candidate Ed25519 handshake/frame ingress, nested Vote/TimeoutVote/QC/TC verification, fsynced session and authenticated-frame replay anchor, durable frame-reservation token, child-process restart/tamper checks | No listener, TLS identity administration, Core ACK atomicity or external anti-rollback |
| `trillionnium/crates/trnm-poco-node/src/authenticated_transport.rs` | Candidate-only bounded TCP adapter around the authenticated session; length-prefix checks before allocation, read deadlines, response bound and caller-owned replay-anchor handoff | No TLS/static peer administration, peer lease, typed transaction/sync dispatch, Core ACK, signer, proposal/finality or production activation |
| `trillionnium/crates/trnm-poco-node-host/src/persistent_p2p_ingress_bridge.rs` | Candidate bridge to prepared Core ingress and ACK | Connect an independently authenticated listener |
| `trillionnium/crates/trnm-poco-lab-validator/src/p2p_admission.rs` | Candidate peer-admission integration | Multi-host production authentication |
| `trillionnium/crates/trnm-consensus-peer-lease/src/lib.rs` | Unix lease transport, append-only chain, cross-process fencing | Not consensus payload transport or host attestation |

The existing admission frame has a 4 MiB **payload** maximum. Unix credentials
and local test keys do not establish cross-host validator identity. New ports
below are planned adapters; their names do not claim current implementation.

### Established G3 receive provenance (M04-ESTABLISHED-RECEIVE-CLASS-V1)

The existing G3 `transport.rs` local-key and external-identity connections are
separate candidate laboratory adapters from the proposed `dev-p2p-tls-v1`
profile. `receive_classified_v1` returns an inert `EstablishedReceiveErrorV1`
with private original error, authenticated `ConnectionSession`, and a closed
class: `PeerInput(reason)`, `TransportIo`, or `Internal`. It grants no peer
lease, Core receipt, reconnect permission, ACK, signing or recovery authority.
The session comes from the completed receiver-challenged handshake, never from
the rejected envelope's claimed sender/session. The mesh must independently
join it to its exact direction and generation before any lifecycle action.

Only the established receive operation may create a peer-input classification:
bounded frame length/grammar, wrong run, unknown claimed sender, invalid frame
signature, or a valid decoded frame whose sender/session/next sequence differs
from the actual connection. This uses the unchanged strict framed decoder and
immutable validated key-role registry. Socket I/O errors retain their exact
`io::Error`; this class alone does not declare any I/O failure recoverable.
Local already-poisoned state, absent external host-attestation admission and
receive-counter exhaustion are `Internal`, even when the legacy enum spelling
is shared with a peer error. Any future unclassified decoder error is internal.
Handshake entropy, configuration and external identity errors are outside this
established-input classification and must not be relabeled by generic matching.

All failures permanently poison that one connection; no failed frame is
returned and its next-receive sequence remains unchanged. Success increments
exactly once after signature and complete session/sequence checks. Existing
`receive` methods delegate the same kernel and project the original
`FrameError` unchanged, including I/O kind/message, replay and poisoned errors.
Send behavior, wire bytes/domains, frame allocation ceilings and handshake
freshness remain unchanged. A connection must never resume by clearing poison
or resetting sequence; an independent genuine handshake creates a new session.

This slice supplies classification only. The existing mesh still uses the
legacy receive interface and may stop globally; per-peer quarantine, checked
lease/host-receipt cleanup and unavailable-session publication require the
separate mesh consumer integration. Pre-authentication rejection, relay/barrier
policy, durable payload replay and terminal acceptance are not changed.
Real TCP regression must complete the authentic handshake before injecting
bad frame bytes; verify the actual peer/session attribution, unchanged sequence,
poisoned retry, independent healthy connection progress and legacy projection.
It must cover both identity backends, correctly signed wrong-session/sequence/
sender frames, invalid signature and malformed/oversized input, transport EOF,
and local overflow/poison/host-admission failures without additional I/O or
external signing. These are connection tests, not a claim of mesh quarantine
or successful multi-host consensus.

### Owned ingress at shutdown (M04-SHUTDOWN-INGRESS-V1)

Stopping an established mesh does not erase input which a receive worker has
already decoded or already owns behind bounded queue backpressure. Before
workers are joined, the shared stop flag requests finite shutdown; it does not
classify pending work as harmless or authorize CleanStop. The existing mesh
close API and the future terminal-barrier residual consumer retain their own
strict acceptance rules.

An `emit_event` owner observing global stop attempts exactly one nonblocking
send into the existing bounded ingress queue. Success preserves the original
non-cloneable event and reservation for post-join examination. Full or
disconnected ingress records the first attributed terminal failure and returns
an error, releasing the event reservation normally; it must not silently drop
work, wait for a consumer that is joining, allocate a second queue, or invent a
budget exemption. A concurrent receiver disappearance records the same failure
even if stop becomes true between observation and `try_send`. A canceled
superseded edge retains its existing separate discard semantics and cannot
publish into the replacement generation. Global child teardown therefore sets
stop rather than pretending every edge was superseded; an actual child panic
remains a retained terminal failure even while stop is already set.

The acceptor owns only its inbound child subtree. Joining that subtree must
not release the registry-wide directed leases: a separately owned outbound
worker may still be finishing its bounded idle revalidation or send path. The
mesh owner releases remaining global leases only after every top-level worker
has joined, both on normal close and failed commissioning. Individual workers
retain their existing exact-direction release behavior. A genuinely missing or
invalid outbound lease remains an internal failure even during stop; there is
no stop-based exemption to fence validation. A deterministic regression holds
a real authenticated outbound session and admitted lease across the inbound
join, then permits its original worker-side idle check before final global
release; a deliberately missing token must still fail the same check.

A successfully decoded frame waiting for its original byte reservation remains
subject to both peer and global ceilings. If global stop ends that wait, record
a terminal failure before releasing that frame; do not mint an unbudgeted mesh
owner. Superseded-edge cancellation is still separate. Inbound nontransient
readiness or receive errors remain terminal even if global stop races their
return. Only the existing explicitly transient I/O class caused by socket
shutdown retains the quiet shutdown treatment. Local state, malformed/signature
errors, mutex failures and resource accounting errors are never relabeled as
transient to complete a campaign. A first retained failure is immutable.

Regression uses completed authenticated TCP handshakes and original decoded
frames to exercise stop with an available count slot, exhausted count capacity,
a disconnected receiver and exhausted byte capacity. It checks exact retained
bytes/session, finite join, unchanged budget ceilings and complete reservation
release; nontransient errors racing stop still fail while superseded cancellation
and explicit transient I/O retain their old behavior. This producer change alone
does not implement peer quarantine or authorize terminal-barrier completion.

### Established peer quarantine (M04-PEER-QUARANTINE-V1)

The G3 mesh consumes only the closed `PeerInput` result of
`receive_classified_v1` after its authentic handshake. A private process-local
registry is frozen from the actual directed peer plan before workers start;
it retains at most one immutable first rejection per admitted incoming identity,
with the original remote/session/generation and closed reason, plus checked
reconnect/recipient counters. It accepts neither an envelope-selected identity
nor a string-matched generic error. Transport I/O retains its existing explicit
transient policy. Internal/poison/resource faults and failed external lease or
host-attestation checks remain global failures.

Publication is serialized with lease admission. It first revalidates the actual
inbound lease/host receipt and exact generation, then pins the current directed
lease coordinates and marks that identity quarantined before any cleanup or
lifecycle event. This mark is irreversible for that mesh incarnation. A new
handshake cannot erase it: authenticated inbound reconnect is refused before
replacement generation or external admission, and outbound reconnect checks the
same closed registry inside the admission lock. Pre-authentication errors retain
their existing policy; this is not an unauthenticated-IP deny list.

The acceptor owns and joins the precise offending inbound worker and its matching
outbound worker, interrupts only those owned sockets, and confirms release of
each pinned external lease and independent host receipt. A stale worker cannot
release a replacement: exact directed session/generation equality and admission
serialization are mandatory. Completed cleanup publishes the ordinary unavailable
session facts; absent/replaced handles, panic, poisoned mutex, stale scope or
cleanup/RPC failure stop the whole mesh. Tokens and receipts remain available
for the existing retry path on uncertain release. Global shutdown joins all
remaining workers and checks outstanding cleanup; it must not silently discard a
quarantine retirement still in flight.

`MeshSendDispositionV0::Quarantined` is distinct from Queued and Backpressured.
The ordered outbox retires only that destination's original obligation with
separate checked counters; it does not count a queued/transmitted frame or byte,
or claim consensus progress. Healthy destinations retain their order and their
bounded budgets. Frames queued before publication and not already in a socket
write are canceled by that worker's retirement, with normal reservation release. No previously recorded
fault or unavailable-session obligation is cleared; the controlled campaign
still cannot claim CleanStop/full participation with a quarantined validator.
These are process-local containment observations, not equivocation/finality
proofs or restart authority.

Required regressions use three real authenticated TCP identities: bad B's
classified frame is refused, its exact worker and leases retire, B's fresh-session
reconnect remains refused, and healthy C continues exchanging strict frames.
They also require exact attribution for a claimed foreign sender, bounded repeat
counters, independent host/external release failure, a stale-generation cleanup
refusal, genuine child panic, strict global internal failure and outbox byte/
recipient accounting. Synthetic topology scheduling tests do not establish
cryptographic acceptance. No full-fleet, public-network or performance claim
follows from this local candidate containment slice.

Already admitted ingress owners from that identity are canceled at the bounded
consumer boundary (one queue owner per receive call), with checked frame/byte
counters and their original reservation release. Same-generation session must
match the immutable rejected owner; only genuinely older owned generations may
also be canceled. Lifecycle unavailability is retained. Publication shares the
existing admission lock with finite outbound queue admission and with durable
payload-replay admission, so a peer rejection cannot manufacture an internal
missing-lease failure. A syscall already in flight at publication is not claimed
to be retracted. The terminal close consumer checks the quarantine registry
after joining all producers, before accepting even otherwise valid Park residuals.

A completed closed `PeerInput` classification is never erased by a concurrent
supersession cancel. The acceptor must join the old worker before releasing its
lease, so that worker publishes from its actual old facts; the replacement path
then completes exact quarantine cleanup and refuses the new admission. The
completed rejection publishes its bounded lifecycle with one nonblocking send;
an unexpectedly full or disconnected lifecycle queue is an internal fatal
failure, never an unbounded wait behind a worker join. A global stop racing that
completed rejection retains a terminal failure, even when supersession was also requested. A completed closed `Internal` classification
also always retains its original failure despite cancel/stop; poisoning, local
cursor failure and host errors cannot be relabeled as supersession. Ordinary
canceled reads and transient I/O keep their existing separate semantics. Every
public close joins and attempts all remaining releases before returning the original retained internal failure;
ordinary cleanup success alone still grants no terminal acceptance.

### Candidate authenticated socket seam

`CandidateAuthenticatedP2pTransportV0` is the socket seam for the candidate
authenticated-transport profile, separate from the G3 laboratory adapters. It
is compiled only by the explicit
`candidate-authenticated-transport` feature (and re-exported by the host's
`candidate-networked-authority` feature). `bind` validates the supplied
validator set against the consensus parameters and switches the listener to
nonblocking mode. `accept_one` polls one connection and serves it
synchronously; it creates no worker thread and has no hidden queue. The
configured connection cap is at most 16 and zero is rejected.

Each connection reads a four-byte big-endian length before allocating. A zero
record, a handshake over `P2P_SESSION_MAX_HANDSHAKE_BYTES_V0`, or a frame over
`P2P_SESSION_MAX_FRAME_BYTES_V0` is rejected before the body allocation. The
handshake has a two-second read deadline and the frame has a five-second read
deadline. The adapter then calls `PocoNodeP2pSessionV0::open` and
`accept_frame`; with `accept_one_with_replay_anchor`, the caller-owned replay
anchor is used so the session/frame reservation is fsynced before the callback
is exposed. The callback returns a bounded response (at most 8 MiB), which is
written as another length-prefixed record.

This seam deliberately has no message-kind router. The callback receives an
authenticated consensus frame only; it cannot by itself admit a public
transaction, download state, acknowledge Core, acquire a peer lease, invoke a
signer, propose, or finalize. `AUTHENTICATED_TRANSPORT_PRODUCTION_ACTIVATION_V0`
is a compile-time `false` constant. The two unit tests cover zero-length and
oversized-prefix rejection before allocation; the existing session tests cover
signature, replay, persistence and restart semantics. A host that uses
`accept_frame_with_durable_reservation` receives a private
`PocoNodeP2pDurableFrameReservationV0` only after the replay-anchor fsync; its
peer/session/sequence/digest fields cannot be caller-constructed. This token
is the required handoff fact for a future typed public/sync dispatcher, but it
does not acknowledge Core. A production listener
still requires the TLS/static-peer identity profile above, a host-owned peer
lease, typed M05/M13 dispatch, exact ACK recovery, and multi-host acceptance.

## Bounded diagnostic ownership

The established receive error retains its original class, complete authenticated
session and source error; its large session record is heap-owned rather than
copied into every Result stack slot. Fleet/restart equivocation errors and the
private lease-renewal failure likewise retain the exact validator identity in a
boxed diagnostic field. This changes only the in-memory Rust error layout, not
peer bytes, signature domains, error classification, lease rules or quorum.
Callers still join the error's original session with the live directed mesh;
smaller diagnostics never authorize re-attribution, reconnect or acceptance.

## Interfaces

Large mesh ingress, connection/signing owners and restart park/ack state variants
retain complete owned values behind boxes.
This is a process-memory representation change only: canonical bytes, validation,
resource limits and linear authority consumption remain unchanged.

`ConnectionPeerV1` groups the expected run/local/remote identities before the
existing handshake verification. `ExternalFrameSigningV1` groups the exact role
key, context and producer passed to the existing signature-verifying encoder.
`FleetCampaignTimingV1` supplies the same four explicit timing fields to the
validated campaign constructor; encode/decode order and field checks are unchanged.
The wrapper types grant no authentication, session or signing authority themselves.

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

The payload replay journal, body store and recovery owner pin directory identity
separately from regular-file identity. Directory device/inode, owner/group and mode must still match the held
descriptor and canonical pathname before and after use. Directory link counts
may change as children are created or removed (including ordinary files on APFS),
so they are not namespace identity. Journal, lock and head files still require
one link and exact file identity; replacement, permission and symlink checks
remain fail-closed. The child-publication/reopen regression exercises actual
WAL admission and exact replay; this is not an external rollback claim.
Recovery retains its original captured endpoint-label preimage for compatibility;
that opaque generation label is not a live directory-metadata comparator. Child
publication and acknowledgement must leave the label stable while the same owner
is alive. A reopened daemon still requires its existing socket-bound handshake.
Canonical pathname validation is unchanged: macOS qualifications use a canonical
private temporary root rather than treating the host's /var alias as authority.

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

The persistent candidate mesh retains its first terminal failure before shutdown.
That same first failure emits one bounded stderr diagnostic at the worker boundary,
so a peer's resulting EOF and coordinator cleanup cannot erase the originating
local reason while the node joins other workers. Direction and remote identity
are retained; reason text is escaped and capped at 512 characters. Later failures
do not replace or duplicate the first diagnostic. Logging failure never changes
the retained cause or disables the stop flag. This is operational attribution,
not signed evidence, a peer offense, or authority to relax the Ready/Start barrier.


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

## M04-DIRECT-TERMINAL-CARRIER-V1

The candidate authenticated frame registry adds kind17 `TerminalBarrier` for
the M15 direct-seven Prepare/Park shutdown protocol. Kinds1–16 and frame-v2
signatures/nonce/session/sequence semantics are unchanged. Its bounded, closed
inner phase codec is admitted only through the original authenticated inbound
mesh owner. It is excluded from ordinary consensus, sparse relay and restart
collectors; transport authentication never converts it into finality, signing
or restart authority. M15 checks the exact fleet and local terminal state.
