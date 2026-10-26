# Trillionnium Chain post-quantum transition, rev1 (HOLD / NO ACTIVATION)

Development branch only. This is a **real offline ML-DSA-65 / ML-KEM-768 conformance increment** and an inventory of remaining gates; not a claim of a post-quantum Chain. The selected mainnet target remains `pon-nakamoto-v1`, which is NOT an active full node. No existing PNW1/W1, transaction, difficulty, signing or fork-choice byte is changed here.

Machine state: [`config/pon/post-quantum-transition-v1.json`](../../config/pon/post-quantum-transition-v1.json). The existing `config/consensus-mainline.json` and `config/pon/devnet-v1.json` keep their false activation flags and their actual 2048/1048576-byte limits. An isolated prototype MUST NOT use either of those names/identities to claim consensus acceptance.

## Why signature substitution cannot be a drop-in change

The native/classical M01 crypto and reference ledger authenticate Ed25519 signatures. Pure ML-DSA-65 has a 3,309-byte signature and a 1,952-byte public key; the prototype's 176-byte signed statement plus signature plus two-byte signature length is **3,487 bytes**, already exceeding the existing 2,048-byte maximum transaction size before any legacy transaction body. With `max_block_bytes=1,048,576`, the corresponding 256-transaction worst-case batch also needs re-evaluation. Proposed 8KiB transaction / 4MiB block values are **research hypotheses**, not silently activated parameter changes; actual wire, fees, execution, mempool and peer quotas must be profiled and independently accepted.

## TPQ1 research envelope, exactly 176 bytes before signature

All numbers big-endian. Concatenation is exact. Unknown bytes and algorithm identifiers must reject; no Ed25519 or hash-only downgrade is permitted.

| Byte range | Field | Boundary |
|---|---|---|
| 0–3 | `TPQ1` | canonical magic |
| 4 | `1` | version |
| 5 | `0x65` | pure ML-DSA-65 algorithm only |
| 6 | `1..6` | transaction, artifact, evaluation, release, custody, peer identity |
| 7 | `0` | reserved (nonzero rejects) |
| 8–39 | network/chain binding | 32 exact bytes |
| 40–71 | owner/operation context | 32 exact bytes |
| 72–103 | public-key ID | `SHA256("TRNM/PoN/PQKey/v1\\0" || canonical DER SPKI)` |
| 104–111 | owner generation | nonzero u64 |
| 112–119 | operation sequence | nonzero u64 |
| 120–127 | expiry | nonzero u64; offline verifier requires current time <= expiry |
| 128–175 | payload commitment | `SHA384("TRNM/PoN/PQAuth/ML-DSA-65/v1\\0" || "payload\\0" || BE64(payload length) || payload)` |
| 176–177 | signature length | BE16 `3309` |
| 178–3486 | signature | FIPS 204 pure ML-DSA-65 of **the exact preceding 176 bytes** |

Public keys must parse as exact DER `SubjectPublicKeyInfo` with ML-DSA-65 OID `2.16.840.1.101.3.4.3.18`; no Ed25519 key, extra SPKI parameters, trailing bytes or alternative algorithm can satisfy the reference. Signature verification is by OpenSSL 3.5+ (real keys; no fake return-true provider). The temporary files, local private test key, external `openssl` CLI calls and bounded subprocess are **offline test-only**, never product key custody, an RPC validator, or a deployed signer.

The stable cross-language vector for purpose `release`, network `00..1f`, context `20..3f`, key-id `0x33`×32, owner generation 7, sequence 19, expiry 4000, and payload ASCII `public Cell release manifest hash and consent` has `SHA256(unsigned176)=e7ab1d942db272e5ac779abdfb0ed9fa5fc2318e059d439a33ca3e09773deae0`. The digest is not a signature and gives no authority.

### Conformance test commands

Requires OpenSSL with default-provider FIPS 203/204 algorithms:

```shell
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_envelope.py test_pq_kem.py test_pq_tls.py
```

Tests use actual generated ML-DSA-65 keys, real signature and verification, verify every signed-header byte's mutation rejection, bad signatures, wrong public key, Ed25519 key downgrade, changed purpose/network/generation/sequence/expiry/payload and noncanonical frames. ML-KEM-768 tests exercise real encapsulation/decapsulation, wrong recipient key, and ciphertext corruption (implicit rejection yields a different secret; a decapsulation API need not return an error). The canonical frame only binds content; the actual owner must separately enforce **current authority, withdrawal, durable one-shot use, monotonic generation and rollback**.

The additional `test_pq_tls.py` starts a **loopback-only** real TLS 1.3 OpenSSL server with an ML-DSA-65 certificate, requires the X25519MLKEM768 negotiated group and certificate/hostname verification, and tests explicit wrong-hostname and classical-X25519-only handshake failures. It closes only the **offline primitive and handshake-conformance example**, not a deployed transport integration, persistent peer keys, issuer governance, production authentication, or independent WAN tests.

### Network: encryption is not authentication

ML-KEM-768 raw encapsulation is not a TLS handshake. The proposed `X25519MLKEM768` TLS 1.3 group must be bound to authenticated, version-negotiated identities and an approved PQ/mixed certificate/signature policy. KEM secrecy alone provides neither peer authentication nor anti-replay; ensure 0-RTT, session resumption, KCI, downgrade, eclipse and generation-fencing cases are covered. No P2P listener is changed by this research.

### Chain and Hepta migration gates

1. **M00/M01/M05/M06:** register explicitly versioned PQ transaction and public-key envelopes, chain ID, fees and bounds. Implement native audited ML-DSA with independent FIPS vectors. An Ed25519->PQ account migration must require existing-account authorization while still secure, reject old-key replays, and retain a chain-specific irreversible migration record. A future hybrid/double signature may be a separate profile with its own bounds. No `verify_reference` result is a verified native authority type.
2. **M02/M03/M07/M08/M13:** new signature rules require explicit governance-controlled network upgrade; no silent fallback. Derive chainwork from real work, and separately qualify Grover-style/search, quantum matrix algorithms, mining distribution, hardware advantage, quantum eclipse and deep-reorg economics. SHA-256 commitments and ML-DSA accounts do **not** prove PoN quantum safety. Past public-key exposure, historical key theft and old signed liabilities need a separately accepted migration rule.
3. **M04/M09/M10/M11/M12:** authenticate manifests, shared-base/Cell deltas, evaluation receipts, custody obligations and reward claims with the right PQ identities and purpose domains. Independent evaluate/holdout authorization remains separate; a signature does not prove truthful model improvement or permission to redistribute private weights.
4. **M14/M15/M16/M17:** make ordinary Hepta learning-artifact, withdrawal, `kernel.operations` and final-use owners supply authoritative inputs. Run genuine multi-operator WAN and physical power-cut testing with signed provenance, refresh/revocation, compromised keys, fees/TPS, CPU/RSS/VRAM, p95/p99 and ongoing cryptographic review. No development fixture issues final-use tokens or a deployment approval.

The complete per-module blocking list is present in the JSON. Only independently witnessed evidence for a specific source, implementation, security model and target operators may close its corresponding gate. Repository documentation/tests, including these tests, **cannot** turn `production_activation`, `independent_accepted` or `native_node_integrated` true.
