# M04 P2P / Session / Dissemination technical specification v1

Status: **implementation contract; candidate only**

## Authority

M04 owns peer authentication, negotiated session profiles, replay admission,
bounded framing, routing, dissemination, peer/global quotas and transport
lifecycle. It may delay or reject local work because of overload. It must not
sign, vote, choose a fork, classify a complete application transition, commit a
state root or manufacture finality.

## Interfaces

The public boundary consists of versioned value types and ports:

- `OpenSessionV1(peer_identity, chain, genesis, protocol, limits, nonce)`;
- `AuthenticatedSessionV1(session_id, peer, generation, profile, expiry)`;
- `IngressFrameV1(session_id, sequence, message_kind, payload_digest, bytes)`;
- `IngressDecisionV1(accepted | duplicate | stale | over_budget | invalid)`;
- `DisseminateV1(object_id, audience, priority, expiry, bytes)`;
- `ReplayFloorV1(peer, session_generation, highest_committed_sequence)`;
- `PeerLeaseV1(peer, generation, byte_budget, work_budget, expiry)`.

Transport bytes are never signing or hashing preimages. Decoding yields a
bounded M00 canonical object before M02, M05 or M13 can consume it. A local
queue error is a local availability result, not deterministic consensus
invalidity.

## State machine

```text
Disconnected
 -> Negotiating
 -> Authenticated
 -> Active
 -> Draining
 -> Closed
```

Every transition consumes the exact session generation. Reconnect creates a new
generation and cannot revive old sequence authority. `Active` accepts a frame
only after identity, chain/profile, length, decompression, message-work and
replay checks. Duplicate delivery is idempotent. Gaps may be buffered only
within a finite window; otherwise the session is reset and the missing object is
requested through a fresh lease.

## Persistence and recovery

The durable session record binds peer key, chain/genesis, negotiated profile,
generation, replay floor and previous record digest. A replay floor is advanced
before an acknowledgement that permits the peer to discard retransmission
state. Lost acknowledgement is resolved by fresh durable readback. A restored
old database, copied session directory, generation regression or disagreement
between replay and lease state fails closed.

Persistent production listeners use descriptor-pinned namespaces and explicit
certificate/key rotation. Process-local counters, Unix credentials and
single-host sockets are test evidence only.

## Resource bounds

Every listener has finite connection, handshake, unauthenticated-byte,
authenticated-byte, decompressed-byte, frame-count, nesting, signature-work,
CPU-time, memory, outbound-queue and bandwidth budgets. Limits exist per peer,
per identity, per subnet/transport source and globally. Admission checks length
before allocation and decompression ratio before expansion. Backpressure
propagates without blocking the deterministic consensus core.

## Security

Required controls include mutual authentication, chain/profile downgrade
resistance, domain-bound challenge nonces, certificate/key rotation, duplicate
identity rejection, anti-amplification, slow-reader isolation, fair scheduling
and explicit bans on peer-identity rebinding. Peer scores are advisory and
cannot override cryptographic validity. Discovery input is untrusted. A
Byzantine peer cannot create unbounded retained ancestry, TC references, state
chunks or pending validation work.

## Observability and SLO

The `bounded-io-runtime-v1` profile reports handshake p50/p95/p99, admission
latency, authenticated good bytes, rejected bytes by reason, queue depth,
backpressure duration, retransmit/duplicate rate, CPU per message kind, memory
high-water mark and peer/global quota saturation. Metrics carry no private
payloads or bearer credentials.

## Verification and evidence

Qualification requires independent client/parser interoperation, malformed and
cross-domain corpora, sequence/generation replay mutants, certificate rotation,
peer churn, fragmentation, reordering, duplicate delivery, 0/1/5 percent loss,
20/80/180 ms RTT, bandwidth/CPU exhaustion, slow readers, partition/heal and
multi-host identity tests. Evidence binds exact source and raw packet/metric
roots.

## Activation boundary

M04 is not production-reachable until a persistent authenticated listener,
durable replay authority, cross-platform peer authentication, exact Core ACK
handoff, multi-host campaign and independent security review all pass on one
unchanged source. Until then every production and release flag remains false.
