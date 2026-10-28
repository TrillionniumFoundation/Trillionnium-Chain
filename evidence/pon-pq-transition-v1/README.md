# PQ signature, KEM, TLS and migration — executed local research evidence

Research PR: [#399](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/399). This package is **not** an independent security audit, an activated protocol or a Rust node qualification.

The local environment used Python 3.13.5, OpenSSL 3.5.5, Linux x86_64, and overlayfs-backed /tmp. No Rust toolchain was installed. The exact source bytes executed by the local runner have Git blob SHAs recorded in [local-qualification.json](local-qualification.json). The matching committed blobs are frozen in this PR. The raw test results, not reconstructed pass claims, are in [local-unittest.log](local-unittest.log).

Run exactly from `formal/pon-nakamoto-v1`:

```shell
python -m unittest -v test_pq_envelope.py test_pq_kem.py test_pq_tls.py test_pq_account_migration.py
```

Observed: **18 tests / 18 passed**, 0 errors or failures in 4.749 seconds. A separate five-run repetition of the eight-connection SQLite race passed locally. The OpenSSL primitives and TLS handshake are real, not mocked. No deployed keys, external providers, real Chain nodes, user data or remote hosts were touched.

The strict envelope is 3,487 bytes with ML-DSA-65 and cannot be accepted by the installed 2,048-byte transaction limit. Historical Ed25519 approvals, reorg consistency, live network rollout, PQ signature fee/size accounting, independent evaluators, audited native crypto key custody, future ML security and quantum-cost PoN work qualification remain blocked. The migration journal proves local duplicate restraint, not account authority, global consensus or physical anti-rollback. No test program can issue the requisite production signatures/evidence.

All original development mainline production flags remain unchanged and false. Missing native integration and quantum work security cannot be closed by this package.
