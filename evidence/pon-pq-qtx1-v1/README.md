# QTX1 actual local OpenSSL research qualification

Scope: **one isolated post-quantum transfer candidate** atop draft PR #399.
No compiled Rust node, live peer network, consensus transaction, real account
debit, final-use capability or production activation is produced.

The exact Git blob SHA-1 of all three Python source files was checked against
the GitHub branch before reporting the results:

| Source file | Git blob SHA-1 |
|---|---|
| `formal/pon-nakamoto-v1/pq_envelope.py` | `27e40b04ac8eaa381ad4dc017f23f226f99f3f41` |
| `formal/pon-nakamoto-v1/pq_transaction.py` | `c8ac18136ef447eaa958111392eee05f92819aac` |
| `formal/pon-nakamoto-v1/test_pq_transaction.py` | `9b7a5a8e469db90f1ba8ce8c694b133521fb3fd2` |

Actual isolated execution: Linux x86_64, Python 3.13.5, OpenSSL 3.5.5.
Command: `python3 -m unittest -v test_pq_transaction.py`.
Result: **12 tests, 0 failures, 1.282 seconds**, including fresh real
ML-DSA-65 key generation, signature verification, all 159 signed body
byte mutations, purpose substitution, replay preflight, exact lengths,
fee/overflow, noncanonical types and hostile key checks.

[Test output](local-unittest.log) and [machine result](local-qualification.json)
are included, with the exact source hashes and explicit false production
claims. This was **not** a full Git checkout; there was no `cargo`/
`rustc` in the isolated test environment, no independent operator or
quantum cost/security assessment, and no installed consensus integration.
Local source blob equality does not replace later comprehensive qualification.
