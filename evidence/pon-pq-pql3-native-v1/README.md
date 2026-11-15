# PQL3 native structural verification evidence — local only

Parent research: Chain PR #442, `6c63f18795e8937e7e8ea11b757fcdbd2ff1e59c`. No mainline mutation or production/activation change.

Executed in an isolated Linux x86_64 container with Python 3.13.5, Debian C compiler 14.2.0, OpenSSL 3.5.5. Two reproducible runs:

- Normal C11 strict compile and `python3 -m unittest -v test_pql3_native_verify.py`: **14 PASS, 1 SKIP, 0 FAIL**. Exhaustive byte mutations for fixed source header, entire generated state, PQL2 and pinned expected values.
- C11 AddressSanitizer + UndefinedBehaviorSanitizer: **14 PASS, 1 SKIP, 0 FAIL**. Instrumented loops use representative field-boundary mutations, not the exhaustive normal-loop count.

The one **SKIP** is the explicit test importing `pq_genesis_state_bridge` from the complete parent repository; it was not available in the isolated source-only local test directory. Execute that test on the actual stacked PR checkout to establish byte parity with the original PQL2 implementation. Neither run includes Ed25519/ML-DSA signing: the upstream PQG1 cryptographic checker remains an independently required gate. No Rust toolchain/full PoN repo, physical failure, WAN, installed Chain execution, signed source anchor, HSM or independent external audit was run.

The counterexample where a fully self-consistent attacker-rehashed PQL2 input **and attacker-chosen anchor** passes remains deliberately tested; a new independent source-history ownership check is mandatory. The C verifier returns a string explicitly denying authority and does not mutate chain state.

The source and exact raw log hashes are in `local-qualification.json`. Retain original stdout/stderr and do not rewrite them to claim all 15 tests executed or production safety.
