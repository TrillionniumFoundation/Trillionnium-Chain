# Test compilation and measurement boundary

The workspace [Cargo manifest](../../../../trillionnium/Cargo.toml) selects
test-only package optimization for `trnm-protocol` (level3) and `trnm-mvcc-fee`
(level1). Both explicitly retain `debug-assertions = true` and
`overflow-checks = true`. Existing SHA2 test settings remain unchanged.
[Cargo's profile specification](https://doc.rust-lang.org/cargo/reference/profiles.html)
defines these separate compiler settings and package overrides.

The purpose is to reduce test-mode control and traversal overhead in repeated
full sparse Merkle root/state and commitment-cache checks. All original Rust
test sources, assertions, inputs, 65,536-key and8MiB boundaries, canonical root
comparisons, error cases, command matrices and registered execution limits remain
required. No test is removed, marked ignored or replaced with a smaller instance.
Optimization changes compiled test code; it is not evidence that the tests have
passed. Actual completion of the exact committed-source suite is necessary.

These entries apply to the `test` profile only. They do not redefine `dev` or
`release`, modify signed work or ledger bytes, change task admission, replace full
proof verification, or select a different consensus implementation. Test-profile
executables must be identified separately from development/release artifacts.
Compilation time and warm-cache preparation remain measured separately and count
toward the registered whole-campaign budget. A compile-only success is not a
verification result.

The preceding exact-source local native-suite timeout remains a failed
observation, including incomplete targets and the actual external parent result.
Other-source passes and hosted CI results cannot overwrite it. A subsequent
qualification uses a fresh namespace, binds its own source/tree, Cargo graph,
lockfile, compiler settings, actual binaries and full command receipts, and keeps
the original native1,200-second and whole-campaign limits. If it fails, that
failure is retained too.

Any measured improvement applies to the recorded test build, host, cache and
workload. It is not production TPS, verification cost on release nodes, a
fastest-miner lower bound, attack availability, neural contribution, independent
operator acceptance or public-network readiness. Those remain separate
[performance acceptance](PERFORMANCE_ACCEPTANCE.md) and
[work qualification](WORK_PROFILE.md) requirements.
