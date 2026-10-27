# M04 post-quantum peer identity / TLS-exporter research V1

**Scope: offline loopback-native C and Python reference only; HOLD_NO_GO; no production P2P, PoN, W1, QTX1, Hepta Final-use or activation changes.**

Parent: Chain PR #413 (head fcd52964b3a2fadba0dec86702775cddf4cc0200); historical PQ ancestors #408, #406, #405 and #399 remain unchanged. The native OpenSSL C probe is an independent experiment, NOT a Rust node integration.

## Actual mutual-authentication boundary

The C probe builds with gcc/cc against OpenSSL 3.5.x and listens only on 127.0.0.1. Both peers present real ML-DSA-65 self-signed development certificates, require TLS1.3, X25519MLKEM768, trusted peer certificate verification and exact 32-byte SHA256(domain || DER-SPKI) key-id pinning. The client additionally validates the expected DNS hostname. The server refuses a missing or untrusted client certificate, and the client refuses a wrong server cert/hostname. A successfully negotiated classical X25519-only connection still fails the strict group check. A handshake return alone does not authorize application traffic: the probe exchanges PING/PONG only after verifying the entire identity/group policy.

Both peers independently derive a 32-byte TLS exporter using label EXPORTER-TRNM-PQ-P2P-v1, with the 96-byte context of expected network, genesis and work-profile bytes. The research probe outputs SHA256(domain || exporter) only, not exporter keying material. Correct mutual peers observe the same channel tag; changing the network context changes the tag. This is a local TLS property, not a global authenticated governance policy.

## PPH1 signed observation

The separate Python reference defines exact 256-byte PPH1 plaintext followed by a 3,487-byte TPQ1 purpose=6 *real ML-DSA-65* signature envelope. PPH1 layout:

| Offset | Field |
|---|---|
| 0..3 | ASCII PPH1 |
| 4..7 | version=1, remaining three bytes zero |
| 8..39 | network (32) |
| 40..71 | genesis (32) |
| 72..103 | profile (32) |
| 104..135 | signer key-ID (32) |
| 136..167 | receiver key-ID (32) |
| 168..199 | host-verified TLS channel tag (32) |
| 200..207 | owner generation (u64 big-endian) |
| 208..215 | sequence (u64 big-endian) |
| 216..223 | expiry (u64 big-endian) |
| 224..255 | nonzero nonce (32) |

Signature context is SHA256(domain || genesis || profile || receiver key-ID). Verifier separately receives the **actual TLS-exported** tag, trusted peer public key and identity, expected network, genesis, profile, generation and sequence, plus a local timestamp. Validity lasts no more than 60 seconds into the future. The remote wire never selects its own trusted exporter. Changing header bytes, signer, expiry, generation, network or receiver fails closed. Same signed frame cannot verify under a fresh TLS exporter. The returned research observation has NO peer grant, admission, chainwork, verified model or key-rotation authority.

## Evidence and limitations

Local command: cd formal/pon-nakamoto-v1 && python3 -m unittest -v test_pq_mtls_probe.py

On Linux x86_64 with Python 3.13.5, OpenSSL 3.5.5 and cc (Debian 14.2.0-19): 11 tests passed, 0 failures. Actual C binary was compiled with -std=c11 -Wall -Wextra -Werror -O2 and -lssl -lcrypto. The three new source files were compared to exact current Git blob SHA-1 identities, as was their unchanged ancestor pq_envelope.py. Original raw unittest output and a bounded scope/host qualification JSON are retained in evidence/pon-pq-peer-mtls-v1.

**Mandatory future blockers**: no product Rust M04/M15 service wiring; no externally trusted peer roster or real operator key provisioning/HSM; no independent WAN nodes, epoch/peer revocation, encrypted multi-session resumption/0-RTT or eclipse/Sybil defense; no durable replay guard for repeated same-channel PPH1; no real Hepta ownership, QTX1 state execution or chain activation. No signature test settles W1 useful-work quantum hardness or qualifies the whole Chain as post-quantum secure. Keep HOLD_NO_GO and independent acceptance false.

## Threat decisions

- A valid self-signed test certificate in a local CA file is not proof of independent operator governance or global membership.
- A pure classical key share is never accepted just because TLS1.3 completed.
- A caller must pin the peer key from independently authorized configuration, not a wire field.
- A signed PPH1 returned after a different TLS session is not current authentication.
- Local PING/PONG after completed mutual verification does not establish a production node or full authorization path.
- Product code MUST have its own rate limits, replay/lease owner, certificate rotation/revocation, protocol downgrade policy and independent tests. The C probe has none of these authorities.
