# PCS1: bounded, multi-provider PQ Cell retrieval

Status: **RESEARCH ONLY — HOLD_NO_GO — DO NOT ACTIVATE**

Base: PR #440, commit 5396fb177fef3b15aa325573f06b45a26bddc738. This branch is a strictly additive child of the existing PQ research chain #399 -> #405 -> #406 -> #408 -> #413 -> #417 -> #419 -> #424 -> #427 -> #431 -> #434 -> #440. No production, W1/PNW1, difficulty, Chainwork, active Ed25519 ledger, PQ transfer, model adoption, or Hepta Final-use authority is changed.

## Implemented

Source: formal/pon-nakamoto-v1/pq_cell_swarm.py
Tests: formal/pon-nakamoto-v1/test_pq_cell_swarm.py

PCS1 connects several **real OS peer processes** on literal 127.0.0.1 through bounded TCP framing. The server is explicitly loopback-only and uses ephemeral test-key files. Requests contain BE32(217) plus the exact inherited 217-byte PCQ1 challenge. Replies contain BE32(n) plus the inherited signed PCR1 response, with a strict maximum of 12 + 1MiB + 1 + 12*48 + 3487 bytes. Oversize length is rejected before payload allocation. This is **not** an authenticated public P2P transport.

Every retried chunk request has a fresh 32-byte nonce, provider key binding, generation, sequence, index, and bounded expiry. The client verifies real OpenSSL ML-DSA-65 via the existing exact pq_cell_custody.py and pq_envelope.py, checks canonical SHA-384 chunk Merkle paths and requires independently supplied expected catalog digest, release identity, and PCB1 whole-object content ID. Provider signatures alone cannot promote arbitrary catalog bytes to a valid model release.

Per-request constraints: <=8 peers, <=4 client workers, <=8 attempts/chunk, <=300 seconds configured wall budget, <=1MiB/chunk, <=4096 chunks and <=64MiB per object. Client worker count is further limited by actual provider count, preventing oversubscribing a single signed provider. At most one batch of futures is in memory. Complete downloaded bytes are rehashed from a new local file using the inherited PCB1 SHA-384 domain, rather than trusting a remote Merkle commitment in isolation.

The historical idle-timeout implementation did not enforce that total wall
budget against a slow-drip peer. The [deadline/native-crypto refinement](PQ_CELL_DEADLINE_NATIVE_CRYPTO_V1.md)
propagates one absolute deadline through key parsing, network and crypto work,
interrupts active sockets/children before joining workers, and checks readback
and publication. Its real TCP regression evidence is separate from the original
30-test run below. Uninterruptible filesystem calls and OS scheduling are not
hard real-time guarantees; post-link failures require caller reconciliation.

Partial files are not published. After complete content verification, an exclusive hardlink makes the finished object visible without overwriting an existing object. A local failure removes its unpublished staging path. Existing paths and symlink leaves are refused. This does not protect a hostile filesystem parent being replaced concurrently; native directory-fd and OS isolation remain production blockers.

The result is **FetchObservation**, a non-authoritative diagnostic. Its failed_attempts merges Busy, timeout, missing, forged and invalid results; these are not interchangeable fraud judgments. No release, custody reward, model adoption, trusted grant, Chainwork, Final-use or storage contract can be constructed.

## Executed counterexamples

Exact source, command, raw output and environment appear in evidence/pon-pq-cell-swarm-v1/.

The combined existing and new suites produce **30/30 PASS** on Linux x86_64, Python 3.13.5 and OpenSSL 3.5.5. PCS1 adds 15 tests using two honest and one malicious independent OS processes under ONE administrator, genuine ML-DSA-65 signed responses, corrupt signature fallback, replay/expired token rejection, attacker-signed alternate catalog refusal, tampered whole weight identity, wrong public key, wrong network/release, invalid BE32 size, all bad providers, no partial publication, immutable output, symlink refusal, strict bounds and nonexistent grant fields.

A first exploratory single-provider test failed because 4 concurrent client requests saturated the server's 2 slots before retries. The downloader was corrected to cap active workers by actual provider count. Only the subsequent full passing run is credited as passing; the failure remains documented.

## Still OPEN — production blockers

- M00/M01: audited native Rust ML-DSA/ML-KEM provider and genuine HSM custody, agreed versioned transaction and block size/fee/gas limits.
- M04/M09/M15: real mutually authenticated PQ hybrid TLS peer service, independent operator provider discovery, Sybil/eclipse admission and CPU bandwidth fairness, signed peer rotation and cross-node anti-rollback.
- M09: ongoing storage proofs, erasure repair, independently owned geographic redundancy, storage payment/challenge economics, hostile WAN and physical-loss testing.
- M10/M11/M14: source-authoritative PCB1/PCA1/Hepta export/withdrawal/release admission, safe model loader with compatible weights, future-window value, local Final-use. The caller of PCS1 supplies pins; this fixture does NOT authenticate their provenance.
- M05/M06/M07/M08/M13: consensus-level PQ nonce, fees, key migration, balances and liabilities, fork/undo and deep reorg, historical trust anchor and durable recovery.
- M02/M17: cryptographically qualified PoN useful-work cost in quantum-adversary and hostile invalid-proof models, independent full-chain security audit, public WAN and sustained throughput.

All production_activation / release / independent_accepted flags remain FALSE. Keep this PR in draft until native production evidence exists.
