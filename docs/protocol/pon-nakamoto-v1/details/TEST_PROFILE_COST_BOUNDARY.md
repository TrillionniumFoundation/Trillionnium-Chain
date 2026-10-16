# Test compilation and measurement boundary

The workspace [Cargo manifest](../../../../trillionnium/Cargo.toml) selects
test-only package optimization for `trnm-protocol`, `trnm-crypto-primitives`
and `trnm-pon-node` (level3), and `trnm-mvcc-fee` (level1). Each explicitly
retains `debug-assertions = true` and `overflow-checks = true`. Existing SHA2
test settings remain unchanged.
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

## Security and finite-service candidate convergence

The Node test-profile setting is combined with the current Worker private-salt
stdout/dry-run and owned-child reaping repairs. This is the exact Cargo profile
previously proposed by PR318, not a change to the public V3 resource policy.
The original CPU burst/refill, deadlines, work targets and both mixed-service
assertions are unchanged. Baseline and optimized executions must keep separate
source, binary, build-profile and output identities. A failed unoptimized run
remains a failure; a passing combined build does not erase it.

Run both original `public_v3_service_campaign` tests, the original Node library
and Worker unit/real-CLI regressions on the combined source. Save the existing
`TRNM_PUBLIC_V3_CAMPAIGN_DIR` and `TRNM_CI_RECEIPT_DIR` outputs outside the
checkout before any pass/fail summary. Retain repeated-run failures and the
complete attempt denominator. No original test is waived or resized.

These are controlled local tests, not a public permissionless service guarantee.
The final paired Hepta source and actual merge must be verified separately;
previous-commit CI cannot qualify the new tuple. Existing queued/running
candidate jobs must not be cancelled to publish this combined candidate.
