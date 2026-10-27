# PQL9 standalone native TPQ1 signature boundary

Status: RESEARCH / HOLD_NO_GO. Strict additive child of PQL8 / PR #486,
head `8d29130ecf5124d21449f0f1d549aacc27de99ad`.

`pq_tpq1_crypto_verify.c` exports a read-only C11 ABI returning 1 **only** after genuine
OpenSSL 3.5+ ML-DSA-65 verification of the exact 176-byte TPQ1 unsigned statement.
It checks all six permitted purpose domains, independent network/context/signer key
ID/generation/sequence/expiry/payload expectations, exact DER ML-DSA-65 SPKI,
SHA-256 SPKI identity and SHA-384 canonical payload commitment. It does not
sign keys, fetch model data, consume a nonce or mutate any persistence, consensus,
P2P, Chainwork, QTX1, Hepta, or release state.

The C ABI expects caller-supplied pins **from an independent trusted owner**.
Passing a self-chosen key, frame and expectations can satisfy the cryptographic
check and is not release or transaction permission. This is a reference
`VERIFIED_SIGNATURE_ONLY` step beyond #486's intentionally unverified parser,
not a finished Rust M01 native signer/verifier, consensus validator or evidence
of post-quantum PoN mining-work hardness. The code is not linked into the
product library, because there is no permission to turn a research probe into
an unreviewed production authority.

Run from `formal/pon-nakamoto-v1`:

```
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_tpq1_crypto_verify.py
```

Requires C11 compiler, libcrypto from OpenSSL 3.5+ and Python 3.13+.
Normal and ASan+UBSan C11 runs each passed all 10 tests on Debian GCC 14.2, Python 3.13.5 and OpenSSL 3.5.5. One positive run covers each of the 6 TPQ1 purposes, 176 statement bytewise corruption cases and 3,309 signature bytewise corruption cases all reject. Each signature probe uses a genuine OpenSSL EVP key and the test also executes a separate OpenSSL CLI verification. No Rust/Cargo qualification is claimed.

The test builds an ephemeral shared library and generates disposable real
ML-DSA-65 / Ed25519 keys with OpenSSL CLI. All signature probes are genuine;
no stub substitutes for EVP_DigestVerify. Tests include a valid signature for
all six domains and forged signature, key/canonical DER downgrade, payload,
context, network, signed-byte mutation, key substitution, time, NULL/short
buffer and resource-budget negatives. The original `pq_envelope.py` is not
copied or modified. Re-run on the complete exact research branch for cross-
implementation byte equivalence and compile the Rust consumer on an authorized
host; current host has no Rust toolchain. Physical failures and audit NOT_RUN.

**Mandatory OPEN:** production-safe Rust audited FIPS 204 ML-DSA provider and
HSM, key provenance and revocation; hard-fork versioned QTX1 size/gas,
mempool, nonce/reorg/legacy liability import/rollback; real hybrid PQ P2P,
Hepta Final-use and independent Cell storage; W1 quantum mining/verification
security and independent public adversarial WAN/physical qualification.
All activation flags remain false. Do not merge into `main` or activate.
