# PQL9 — native ML-DSA-65 TPQ1 signature verification, without authority promotion

**RESEARCH ONLY / HOLD_NO_GO.** Exact parent: PQL8 PR #486 at
8d29130ecf5124d21449f0f1d549aacc27de99ad.
This is an offline C11/OpenSSL conformance oracle. No installed Rust/Ed25519 PoN,
W1/PNW1, Chainwork, transaction limit, Hepta Final-use or production flag changes.

## Actual contract and bounded inputs

PQL8's Rust UnverifiedPqFrame is a **syntax-only** preflight.
The additive pq_tpq1_native_verify.c checks genuine OpenSSL 3.5+
FIPS 204 **pure ML-DSA-65 signatures** for **all six** TPQ1 purposes.
Successful verification is a process-local research observation, **not**
VerifiedTransaction, signer authorization, VerifiedWork, model release
or Final-use capability.

Command (independent caller inputs, not derived from the untrusted frame):

    pq_tpq1_native_verify public.pem signed.tpq payload.bin \
      network32hex context32hex keyid32hex purpose generation sequence expiry now

Before cryptography, refuse malformed/oversize numeric arguments, expired or
zero generations/sequence, wrong purpose, wrong network/context/key-ID, wrong
signature length, changed or oversized SHA-384 payload and all classical-key
downgrades. Canonical SPKI is exactly 1,974 bytes of DER with the fixed
id-ml-dsa-65 OID, zero unused BIT STRING bits and 1,952 public-key bytes.
The pinned key ID is recomputed from SHA-256 of the NUL-separated
TRNM/PoN/PQKey/v1 domain and exact DER SPKI. Signer ID must match the
pinned expectation *and* frame. Cryptography verifies the exact 176-byte
unsigned statement with a 3,309-byte signature; no fallback is permitted.

All inputs are opened as regular no-symlink, single-link files; public
PEM is capped at 16 KiB; signed frames are 3,487 bytes; payload is streamed
up to the 64 MiB contract. The oracle does not load private keys, operate
a network listener, open the Chain ledger or dispense authority.

## Actually executed tests

Exact source SHA-256 and Git blob:

| File | SHA-256 | Git blob |
|---|---|---|
| pq_tpq1_native_verify.c | a14ef90b94642e3fdbe5b85dd8ed74266a432dda36c687325bc938772881b57a | f3aeade9774b1df116fd10c2449404b07ec36afb |
| test_pq_tpq1_native_verify.py | 64885bc220ff2530e56fb5993afa85889b4a7999e5c0e79a1e9b84861c3c80b5 | 1d4fe6a89a44faafadbb5cab1343d5849b66ab2e |

Linux x86_64 / Python 3.13.5 / GCC 14.2 / OpenSSL 3.5.5:
**5/5 native tests PASS** and **5/5 tests PASS with GCC ASan+UBSan**;
Clang 17 strict standalone compilation also passed.
GitHub uploaded source blobs were checked identical to tested files.
Raw stdout/stderr is retained in evidence/pon-pq-tpq1-native-v1/.

Tests create actual ML-DSA-65 signatures, verify purpose 1..6,
reject every changed signed-statement byte, signature forgery, zero
signature, malformed length, mismatched key/context/payload, expired and
changed sequence/generation, noncanonical numbers, Ed25519 key downgrade,
PEM extra data, oversized file and symlink inputs.

These are **standalone exact-source tests**, not full checked-out PQL9
integration tests. Rust Cargo tests were **NOT RUN** (Rust toolchain absent).
External independent cryptographic review, WAN and physical fault tests
were **NOT RUN**.

## Mandatory unclosed blockers

1. Independently audited production Rust ML-DSA verifier, native trusted
   signer authorization and HSM/key custody: a C process exit MUST NOT
   silently create a production authority token.
2. Versioned 2048-byte-incompatible transaction encoding, deterministic
   verification-gas and fee schedule, durable M05-M08 PQ nonce and reorg
   owner, account/liability migration and signed replay consumption.
3. Independently administered monotonic anti-rollback anchors,
   authenticated hybrid-PQ WAN, independent Cell retention and normal
   Hepta export/withdrawal/Final-use ownership.
4. Quantum-effective PoN W1 honest-versus-adversarial work costs, false
   ticket Sybil-safe admission and independent network/security review.

Existing max_transaction_bytes=2048 is smaller than the ML-DSA-65
signature of 3309 bytes. No activation/readiness flag may turn true.
