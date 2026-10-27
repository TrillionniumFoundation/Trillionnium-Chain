# PQN4 native signed Cell chunk verifier — exact local execution

Parent revision: PR #434 `f4050776006ee67de1075fb247df7a848fb12447`.
Research child only; no mainline Chain changes, old Ed25519 transaction migration, W1, production launch or Hepta Final-use authority.

Compiler: Debian cc 14.2.0; OpenSSL 3.5.5 default provider; Python 3.13.5; Linux x86_64. The test compiles C11 EVP verification separately and signs independently created reference frames using actual generated ML-DSA-65 test keys. No private key leaves local temporary test paths.

Commands from `formal/pon-nakamoto-v1`:

```sh
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_cell_native_verify.py
PQN4_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_cell_native_verify.py
```

Both actual run transcripts: **12 named tests / 12 PASS / 0 FAIL** each. Included every 176-byte TPQ1 unsigned-header mutation and every 217-byte PCQ1 challenge mutation, real Ed25519 key substitution, symlink, bad catalog root, pinned release mismatch and 1 MiB exact chunk. Neither run included a Rust full-node, public WAN, independent operators, GPU, physical fault, real model contribution or quantum work hardness experiment. Sanitizers do not provide independent formal memory safety verification.

`local-qualification.json` records exact source SHA-256, Git blob SHA-1, runtime, commands, sample test counts and explicit unaccepted scopes. `normal.log` and `sanitized.log` are raw execution outputs; neither is a production acceptance receipt.
