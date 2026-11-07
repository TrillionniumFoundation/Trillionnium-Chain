# PQN1: bounded native QTX1 ML-DSA-65 signature and preflight conformance (research ONLY)

**Scope:** Additive child of Chain research PR #419 (`2692d69c567f41a6ae4d981cad7a426005efe689`) stacked on #417, #413, #408, #406, #405, #399. Only the isolated native C/OpenSSL reference probe, tests and evidence are changed. This is NOT a complete native Rust M00/M01/M05/M06 or an activated PoN transaction type.

## Security contract / non-authority

The CLI is a single-use, read-only offline verifier. It neither opens nor writes a Chain database, signs a private key, loads a model, grants Final-use, creates `VerifiedWork`, consumes a nonce, nor relays a transaction. **PQN1_RESEARCH_ONLY_SIGNATURE_VALID** means no more than: for the exact caller-supplied bytes, the signature and *caller-provided* account/time/fee fields passed this check. Every field passed on the command line is untrusted unless provided by an independently authenticated production state owner. This tool is not safe to register as a live RPC handler or consensus capability.

- Inputs are bounded regular files opened with `O_NOFOLLOW`, maximum 8,192 transaction bytes and 16,384 public-key PEM bytes. No shell, private key, dynamic script or JSON parser is used.
- Strict QTX1 canonical fixed 144-byte header with <=512 memo bytes and exact appended 3,487-byte TPQ1 ML-DSA-65 frame. Unknown version/type, wrong lengths, trailers and wrong domain are rejected.
- Strict TPQ1 176-byte message and algorithm `0x65`, purpose `1` only, signature-length 3,309, no Ed25519/hybrid/classical downgrade. EVP provider must parse ML-DSA-65; extracted canonical DER SubjectPublicKeyInfo must contain only OID `2.16.840.1.101.3.4.3.18` with 1,952-byte key and no trailing fields. Public-key ID is SHA256 with exact `TRNM/PoN/PQKey/v1\0` domain.
- Signed context = SHA256(`TRNM/PoN/QTX1Context/v1\0` || network || sender), signed payload = SHA384(`TRNM/PoN/PQAuth/ML-DSA-65/v1\0` || `payload\0` || BE64(body_size) || QTX1_body). ML-DSA-65 verifies over the *exact* 176-byte unsigned envelope.
- Transaction identity = SHA384(`TRNM/PoN/QTX1Identity/v1\0` || BE32(body_size) || QTX1_body || signer_key_id), so randomized ML-DSA signature bytes are not additional transaction identities.
- External expected network, account, signer ID, generation, next nonce, clock, active flag, balance and fee policy must exactly match. Fee arithmetic rejects u64 overflow, insufficiency and limits **before** expensive ML-DSA verification.
- This profile deliberately does not change existing `max_transaction_bytes=2048`, PoN transaction rules, the W1 proof, fork choice, Chainwork or Chain activation. PQN1 frames are 3,631–4,143 bytes and cannot be submitted to the installed legacy wire.

## Reproduction

Requires Debian/Linux, C11 compiler with OpenSSL 3.5+ ML-DSA-65 provider, Python 3.13+, inherited `pq_envelope.py` (exact source from #399; do NOT duplicate it in the PR):

```sh
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_native_qtx1.py
PQN1_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  python3 -m unittest -v test_pq_native_qtx1.py
```

Tests compile in a fresh temporary directory. The native binary is neither committed nor installed. The Python test creates fresh disposable ML-DSA-65 keys and cross-checks TPQ1 verification and QTX1 identity using the inherited exact reference. Regression tests reject every signed QTX1 body byte mutation and every TPQ1 statement byte mutation, malformed data, symlink input, unknown signers, attacker-held Ed25519 key, wrong purpose/account/generation/nonce/clock, and fee/balance overflow. Both normal and sanitizer paths passed 10 tests on one local environment. They are not independent cryptographic acceptance.

## Remaining mandatory blockers

1. Implement audited **Rust** ML-DSA verification/key custody in M01, strict versioned M00 wire, native M05 mempool, M06 deterministic fee/nonce and M07/M08 reorganization state; refuse all mismatched or stale signer mappings.
2. Complete fork-aware migration of classical account authority, persistent anti-rollback of real Chain state, post-quantum peer security in M04, and independent Hepta authority receipts.
3. Qualification of W1 quantum effective-work and attacker GPU/ASIC/quantum advantages remains absent. Signature migration alone does not make PoN quantum resistant.
4. Independently operated WAN, malicious-input admission, physical failure, full-node throughput, key/HSM lifecycle, formal/cross-implementation auditing and external cryptographic review remain OPEN.

**Status: HOLD_NO_GO, production activation unchanged (false).**
