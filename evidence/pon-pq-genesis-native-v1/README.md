# PQN2 native genesis verification evidence (local only)

Stacked on PQ research PR #431, without changing consensus or activation.

The proof verifier is C11/OpenSSL EVP with strict Ed25519 point/scalar prevalidation and genuine ML-DSA-65. It never writes ledger state or generates an authority token.

- Source blobs: `pqg_native_verify.c` and `test_pqg_native_verify.py`, pinned in local-qualification.json
- Executed **17/17** normal Python/compiled-C regression tests: `normal.log`
- Executed **17/17** compiled-C ASan+UBSan tests: `sanitize.log`
- Python 3.13.5, OpenSSL 3.5.5, Debian cc 14.2.0 on one Linux x86_64 container.
- All test keys are generated in temporary directories and were not committed.

Tests and hash binding are scope-specific. They do not constitute independent review, whole-chain consensus integration, authentic source-state governance, historic quarantine/nonce migration, HSM custody, WAN qualification, quantum PoN work security or production readiness.

See `docs/security/PQ_GENESIS_NATIVE_DUAL_VERIFY_V1.md`. Production stays disabled.
