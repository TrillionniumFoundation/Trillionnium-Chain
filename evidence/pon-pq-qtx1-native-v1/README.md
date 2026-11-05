# PQN1 QTX1 native research qualification

A standalone C11/OpenSSL 3.5.5 offline ML-DSA-65 verifier and 10 negative/positive test selectors, each run once normally and again with ASan/UBSan. The code is read-only, works only with explicitly pinned caller context, and never returns authority. The exact Python `pq_envelope.py` reference exists in upstream PR #399 and must not be duplicated in the GitHub increment.

Reproduction instructions, wire fields, rejection rules and remaining blockers: `docs/security/PQ_QTX1_NATIVE_CRYPTO_CONFORMANCE_V1.md`.

`native-test.log` and `sanitizer-test.log` are measured test output from the source blobs listed in `qualification.json`. No CI, native Rust production node, public-network test or independent certification is implied.
