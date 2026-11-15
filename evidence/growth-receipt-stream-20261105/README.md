# Growth migration receipt copy and fixed block IDs

Base: `0e1c25d42fff22bec6ec2a08c4fbdff240229858`. The four changed Rust inputs are bound by [source hashes](source.sha256). This is a local component repair, not whole-chain acceptance. Draft/HOLD and every original activation/security/performance gate remain unchanged.

The authenticated source receipt is now copied using a 65,536-byte stack buffer from one verified descriptor. It consumes the complete observed length, probes EOF, rechecks identity and compares the complete original SHA-256 before syncing. No new total receipt-size ceiling is introduced. Pending failed stages remain available. The existing independent cold verification and final source-fingerprint checks remain in place.

Both migration block-ID traversals now use the existing 32-plus-one-byte fixed-field copy. The original `bytes32` validation and SQL conversion failures, including NULL and non-BLOB types, are retained. This bounds owned Rust copies, not SQLite cell memory, whole-process RSS, total work or transaction duration.

## Actual verification

Original workspace, Rust 1.95.0, locked Cargo graph and existing profiles were used with one build job. Native selector: `cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::authenticated_migration:: -- --test-threads=1`.

[Native log](native.txt): **39 passed, zero failed, zero ignored**, including all 36 retained cases and three new controls. New controls cover complete empty/single/multichunk/>1 MiB copies, digest mismatch, concurrent append, ID width and SQL type refusals. This is the selected component suite, not a full original-workspace/all-targets native result.

The [initial compile failure](initial-compile-failure.txt) is preserved: a missing helper import was corrected before the successful run. No native failure was reclassified as success.

Additional checks: formatting; locked metadata; repository check (26 packages, 1,157 Rust files, 3,336 local links); 43 source-integrity negative controls. [Strict Node all-targets Clippy](clippy.txt) with `-D warnings` passed. Hosted gates and independent acceptance are not inferred from these local results.
