# Trillionnium Agent↔User P2P Communication Minimal Spec v0.1

Status: Draft  
Owner: Trillionnium Core  
Scope: Production-side AI agent and consumer-side user communication for PoUW tasks

## 1. Goal

Define a **minimal production-ready** off-chain communication protocol that works with current on-chain PoUW lifecycle:

`OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED/SLASHED`

Design principle:
- On-chain = settlement, dispute, audit anchor
- Off-chain = low-latency interaction and data exchange

## 2. Non-goals (v0.1)

- Not a general chat product
- Not end-to-end media streaming
- Not anonymous routing/privacy network
- Not full DID framework

## 3. Architecture

### 3.1 Control/Data planes

1) **On-chain control plane**
- Task creation/assignment/commit/reveal/challenge/resolve
- Final state source of truth

2) **Off-chain communication plane**
- Transport: WebSocket (required in v0.1)
- Optional later: libp2p/WebRTC
- Payloads signed by sender key

3) **On-chain anchor plane**
- Anchor hashes of critical message bundles and result manifests
- Used for replay/dispute/audit

## 4. Identity & Session

Each side has:
- `addr`: on-chain address
- `comm_pubkey`: off-chain signing pubkey (ed25519/secp256k1, one must be selected per deployment)
- `session_id`: per-task communication session id

Binding rule (required):
- `comm_pubkey` must be bound to `addr` via signed registration record (on-chain param/object or trusted registry mirrored on-chain hash)

## 5. Message Envelope (canonical)

```json
{
  "version": "p2p-v0.1",
  "task_id": "...",
  "session_id": "...",
  "seq": 42,
  "timestamp_ms": 1730000000000,
  "type": "TASK_ACCEPT|INPUT_CHUNK|RESULT_META|RESULT_POINTER|ACK|ERROR|CLOSE",
  "from": "trnm1...",
  "to": "trnm1...",
  "nonce": "128-bit-random",
  "payload": {"...": "..."},
  "payload_hash": "hex",
  "sig": "hex"
}
```

Validation rules (single verifier entry for `version/type/seq/nonce/payload_hash/sig`):
- `version` must equal `p2p-v0.1`
- `type` must be one of: `TASK_ACCEPT|INPUT_CHUNK|RESULT_META|RESULT_POINTER|ACK|ERROR|CLOSE`
- `seq` strictly monotonic per `(task_id, session_id, from)`
- `nonce` unique within session
- `timestamp_ms` within tolerance window (default ±120s)
- `payload_hash` must match payload bytes
- signature must match sender bound `comm_pubkey`

Stable relay auth error codes (v0.1):
- `BadSig`
- `Replay`
- `SeqRegression`
- `TimeSkew`
- `PayloadHashMismatch`

## 6. Minimal Message Types

1) `TASK_ACCEPT`
- Agent confirms assignment acceptance and communication readiness

2) `INPUT_CHUNK`
- User sends incremental input/context
- Payload fields: `chunk_id`, `content_ref|content_inline`, `final_chunk`

3) `RESULT_META`
- Agent publishes result summary + deterministic metadata
- Payload fields: `result_hash`, `model_info`, `compute_receipt_ref`

4) `RESULT_POINTER`
- Agent provides large output reference (object storage/IPFS/etc)
- Payload fields: `uri`, `content_hash`, `size_bytes`

5) `ACK`
- Generic acknowledgement for reliability
- Payload fields: `acked_seq`

6) `ERROR`
- Structured failure with code
- Payload fields: `code`, `message`, `retryable`

7) `CLOSE`
- Explicit session close reason
- Payload fields: `reason`, `final_state_hint`

## 7. Reliability & Timeouts

- Delivery semantics: at-least-once + idempotent processing
- Sender retries unacked frame with exponential backoff
- Receiver deduplicates by `(from, seq)` and `nonce`
- Session timeout defaults:
  - idle timeout: 300s
  - hard timeout: task-specific, capped by on-chain deadline

## 8. Security Requirements

Required in v0.1:
- Mutual auth via signed envelopes
- Replay protection (`seq` + `nonce` + ttl window)
- Integrity via `payload_hash`
- Rate limiting per session/IP
- Audit log append-only at gateway/relay

Recommended:
- TLS everywhere
- Optional payload encryption (X25519 session key) for sensitive tasks

## 9. On-chain Anchoring Points

Anchor at minimum two checkpoints:

1) **Pre-commit anchor**
- Hash of communication transcript segment + input manifest
- Referenced by `commit`

2) **Pre-reveal/result anchor**
- Hash of result metadata + output manifest
- Referenced by `reveal`

Anchor object format (suggested):
- `task_id`
- `segment_start_seq`
- `segment_end_seq`
- `transcript_merkle_root`
- `artifact_manifest_hash`

## 10. Dispute Support

During `CHALLENGED`:
- Challenger may request transcript segment proof
- Agent/user/relay must provide signed envelope sequence + merkle inclusion proof
- Resolver compares:
  - on-chain anchors
  - envelope signatures
  - sequence continuity
  - hash consistency

## 11. Minimal API Surface (v0.1)

Relay/Gateway endpoints:
- `POST /v0.1/session/open`
- `POST /v0.1/session/send`
- `GET  /v0.1/session/poll?task_id=&session_id=&from_seq=`
- `POST /v0.1/session/ack`
- `POST /v0.1/session/close`
- `GET  /v0.1/session/proof?task_id=&from_seq=&to_seq=`

## 12. Backward/Forward Compatibility

- Envelope has explicit `version`
- Unknown `type` must be ignored with `ERROR(code=UNSUPPORTED_TYPE)`
- New fields must be additive, never repurpose existing semantic fields

## 13. Rollout Plan

Phase A (now):
- Implement relay with signed envelope, ack/retry, dedupe, logs
- Add anchor generation in worker flow (`commit/reveal` hooks)

Phase B:
- Add transcript merkle proof API
- Add challenge-time verifier path

Phase C:
- Optional payload encryption + alternate transports

## 14. Acceptance Criteria

- Agent can accept task and complete end-to-end with user interaction over WebSocket
- At least one retry/reconnect path verified
- Replay attack test rejected
- Missing/invalid signature rejected
- Anchor hashes reproducible and match on-chain references
- Dispute sample can reconstruct and verify transcript segment

---

This spec intentionally keeps communication off-chain while preserving on-chain verifiability for PoUW adjudication.
