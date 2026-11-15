# PQL8 — exact ML-DSA-65 SPKI identity in native TPQ1 preflight

Status: **RESEARCH ONLY / HOLD_NO_GO**. Based on PQL7 exact head b9f465f9d8b6f14b8d68331cc63185c48ea95078 (Chain PR #481). This increment does not update main, make Rust/Hepta transaction authorization, activate a node, or change W1, Ed25519 or Chainwork.

## Threat and narrow repair

The inherited trnm-protocol::pq_frame preflight accepted a 32-byte signer_key_id supplied by the caller and required the frame to repeat that ID. It did **not** bind that ID to any independently supplied ML-DSA-65 DER public key. A future caller that mistakes the preflight as cryptographic authorization could accept substituted or unauthenticated signer identities.

The additive Rust functions ml_dsa_65_key_id_from_spki and preflight_unverified_with_spki require one exact canonical DER SubjectPublicKeyInfo (1,974 bytes), with the id-ml-dsa-65 OID (2.16.840.1.101.3.4.3.18), a 1,953-byte BIT STRING with zero unused bits, and precisely 1,952 public-key bytes. The byte grammar fixes the DER prefix (22 bytes) and refuses Ed25519, missing bytes, non-minimal lengths, added parameters, altered OID and trailing data. The reference key ID is SHA-256 of the NUL-terminated domain TRNM/PoN/PQKey/v1 followed by all canonical SPKI bytes. It must equal the independently pinned expected signer ID and frame field.

**This is structural framing and a key identifier only.** It does not validate the ML-DSA-65 key's cryptographic acceptability, verify a FIPS 204 signature, prove ownership of the private key, authorize nonce state, model release, PoN work, Chain/Hepta Final-use, or any transaction. The returned type remains UnverifiedPqFrame. A forged all-zero signature still passes the *unverified* preflight by design; the cryptographic and state owners must reject it separately. Expected context, expected key identity and raw SPKI must come from independently authenticated owner state, never self-certified by the untrusted packet.

## Evidence with exact scope

- New native Rust unit tests: one deterministic SHA-256 vector, pinned-key substitution rejection, all-zero-signature NON-authority; one malformed DER/Ed25519 OID/length/trailing-data suite. Rust toolchain absent from this isolated environment: **NOT COMPILED, NOT EXECUTED**.
- Independent Python and OpenSSL 3.5.5 test file (blob 5a9848b4f665002c6d55c465a4f6e8a0a8efa349): 3/3 tests executed, including real newly generated ML-DSA-65 and Ed25519 DER keys, strict DER mutations and frozen ID. These tests validate the protocol byte oracle, **not Rust execution**.
- Required exact-source Rust qualification when a Rust toolchain is available:

    cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol pq_frame

- Independent C/OpenSSL verification remains in pq_qtx1_verify.c and pq_cell_native_verify.c, separate and research-only. Neither is silently attached to this unverified Rust parser.

## Mandatory open blockers

1. Install and independently audit a real native ML-DSA-65 signature verifier/key-custody owner; forbid any conversion from UnverifiedPqFrame to a VerifiedTransaction or Final-use token without cryptographic and durable owner checks.
2. Replace incompatible production Ed25519 transaction limits and integrate fork-local PQ nonces, fees, mempool, M02-M08 state rollback and migration liabilities under a versioned protocol activation.
3. Establish quantum-effective PoN W1 work security, Sybil-safe invalid-proof validation, independently administered anti-rollback anchors and production PQ hybrid authenticated WAN transport.
4. Complete real Hepta consent/withdrawal/Final-use integration, networked Cell availability/repair, physical power loss, adversarial public network tests and independent cryptographic acceptance.

All release/consensus/public-testnet activation flags remain false; no automatic merge or promotion is authorized by this research receipt.
