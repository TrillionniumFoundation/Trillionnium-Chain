# PCQ1/PCR1 — PQ Cell chunk retrieval and local replay observation (research, HOLD_NO_GO)

This is an incremental M09/M01 **offline** extension of PQ Cell releases in PR #406, with direct TPQ1 purpose=5 ML-DSA-65 signatures supplied by the existing, unchanged `pq_envelope.py`. It changes no mainline PoN consensus, Ed25519 transactions, work bytes, fees, W1 work factor, Chainwork, Hepta Final-use or production activation flag.

## Purpose and authority boundary

The objective is to ensure that a responding peer supplies *exactly* a challenged chunk from a caller-pinned Cell weight catalog and signs the retrieval observation with a genuinely verified ML-DSA-65 key. The signature is not proof that the key belongs to a real custodian, that the peer held bytes before the challenge, that storage is continuously available or that a model may be adopted. RetrievalObservation provides only non-authoritative diagnostic facts, not VerifiedWork, a grant, a storage reward or a final-use token. The one-use SQLite table is purely local; never use it for chain-wide nullifiers, payment, consistency with a reorg or historical rights.

**Critical trust requirement:** The caller must provide *independently authenticated* `expected_catalog_digest`, `expected_release`, trusted provider key ID, requester identity and challenge nonce. Reading these from the same peer-controlled catalog or signed response proves only self-consistency. The current PR #406 PCB1 release format does not itself anchor the new catalog root. The separately signed research PCA1 catalog binding (below) demonstrates one path to obtain a cryptographic catalog pin from an explicitly trusted release signer, but production activation still requires a reviewed versioned release extension, independently accepted PCB1 evaluation/reviewer evidence, immutable catalog selection, and real Hepta export/final-use authorization.

## Binary formats and proof derivation

PCC1 catalog: exactly 157 bytes: magic (4) + version (1) + network (32) + release manifest ID (48) + generation (u64 BE) + total bytes (u64 BE) + chunk size (u32 BE) + chunk count (u32 BE) + Merkle root (48). Whole object <=64 MiB, chunk <=1 MiB, count <=4096, and exactly ceil(total_bytes/chunk_size) chunks.

PCQ1 challenge: exactly 217 bytes: magic (4) + version (1) + network (32) + pinned catalog ID (48) + nonzero nonce (32) + nonzero requester ID (32) + nonzero provider TPQ1 key ID (32) + generation (u64 BE) + sequence (u64 BE) + chunk index (u32 BE) + issued/expiry (two u64 BE); TTL must be <=300 seconds. The trusted caller supplies current time; no source-created wall clock is considered an authority. A provider key's SPKI is validated by the existing TPQ1 verifier.

PCR1 response: magic (4) + chunk index (u32 BE) + chunk length (u32 BE) + raw bytes (<=1 MiB) + Merkle depth (u8 <=12) + 48-byte siblings + exact 3,487-byte TPQ1 purpose=5 signed envelope. Proof siblings are canonical and duplicate-last odd branches must match the immediately preceding hash. A leaf commits domain, BE index/total/length and complete raw bytes using SHA-384. Each internal hash commits a separate NODE domain and ordered children. Catalog ID commits the exact 157-byte catalog. The TPQ1 payload commits the catalog ID, challenge ID, leaf hash and full proof path; its context independently commits catalog and challenge. Changing any field causes verification rejection under pinned expectations.

Exact messages and hash domain separators are encoded by the executable research file, not negotiable by peer data.

## PCA1 — optional PQ release-signer catalog binding (not an installed PCB1 field)

A separate ML-DSA-65 TPQ1 purpose=4 signature commits to `PCA1 || exact PCC1 catalog bytes || release_frame_id || previous_catalog_head`, where `release_frame_id=SHA384(DOMAIN || "release-frame\\0" || exact signed PCB1 release frame)`. The signature binds a 32-byte signer identity, network, generation, sequence, expiry and domain-separated context of the signed catalog/release/prior head.

The receiving caller must independently authenticate the exact original PCB1 release frame **and** the release signer/roster/review/consent facts before accepting the expected release-frame digest. The PCA1 research verifier itself checks the original frame's **canonical purpose only**; it does not re-verify that prior frame's reviewers, independently authorized source or original signature/payload. Treat `CatalogPinObservation` strictly as diagnostic cryptographic signer-to-catalog linkage. It is not a chain canonical release pointer, final-use authorization, storage reward or tamper-proof uniqueness registry. Multiple conflicting PCA1 attestations by the same signer still require an externally owned fork/revocation/equivocation policy.

## Local execution and evidence

```sh
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_cell_custody.py
```

The v1 local campaign executed 13 tests with Python 3.13.5 and OpenSSL 3.5.5 default-provider genuine ML-DSA-65; source blobs on GitHub match the executed local file bytes. Tests include all 217 per-byte PCQ1 mutations; altered chunk, proof and ML-DSA signature; odd-branch Merkle malleability; wrong signer, release, generation, nonce, requester, catalog or expiry; a *fully self-consistent malicious replacement tree under the same release ID*; strict frame and size limits; SQLite foreign schema/trigger/primary-key downgrades; cold reopening, exact retry and eight parallel independent SQLite connections allowing exactly one FIRST_RECORD. The v2 follow-up adds two real-signer PCA1 tests and executed **15 PASS** on the updated exact source (see `evidence/pon-pq-cell-custody-v2/`). The v1 raw evidence remains immutable and bound to its older source. This is a local environment, not independent operator acceptance.

## Remaining critical blockers

1. Authenticated PQ catalog root publication must be part of the production release/Chain/Hepta owner contract; current PCB1 does not sign it, and standalone research PCA1 is not a production chain pointer.
2. A signed retrieval can be produced by downloading bytes **after** receiving a challenge. Periodic challenge sampling does not prove geographic retention or continuous data availability.
3. Admission CPU/bandwidth cost, source diversity, DHT discovery, loss/recovery/repair, erasure coding, network Sybil and eclipse resistance remain unbuilt.
4. Local SQLite is not globally replicated, rollback-proof, owner-provisioned or acceptable for payment; recovery needs a production state machine and chain reorg semantics.
5. Real native Rust ML-DSA custody verifier, key/HSM provisioning, PQ transport integration, public WAN/power-loss tests, external cryptographic review, quantification of PoN quantum work security and full Chain PQ migration remain required.

**No product or production security flag is promoted.**
