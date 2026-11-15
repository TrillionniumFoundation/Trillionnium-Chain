# Native verification of frozen source f388f46d

The [reconciled result](native-frozen-f388f46d9df1/reconciled-verification.json)
binds source `f388f46d9df150a3599b9d961b48918b3ff1fb48` and its exact tree,
Cargo lock/graph, Rust 1.95 toolchain and measured OpenSSL provider inputs.
It covers M06 (`trnm-mvcc-fee`) and the dependencies compiled by its retained
all-targets/all-features commands. It is not a full-workspace or deployment
qualification.

Actual execution completed **236 passed, zero failed, seven original ignored,
zero filtered**, across 25 test targets. The complete compiled 243-entry
[test roster](native-frozen-f388f46d9df1/actual-test-roster.json) agrees with
the [retained execution transcript](native-frozen-f388f46d9df1/m06-tests.log.gz).
The [strict Clippy log](native-frozen-f388f46d9df1/m06-clippy.log) records
`--all-targets --all-features -- -D warnings` returning zero. Cargo metadata
resolved 175 packages and 26 workspace members; formatting and preflight passed.
Source and provider environment, CLI, static libcrypto and static libssl hashes
were unchanged before and after these observations.

The original environment has `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`,
`CARGO_BUILD_JOBS=1` and `RUST_TEST_THREADS=1`, with no custom `RUSTFLAGS`.
The successful run used a fresh task-owned tmpfs target and temporary directory
after shared disk exhaustion and a mixed-metadata cache were observed.

Earlier failures remain present: the first default-profile build returned 101
on ENOSPC without executing the test suite; the original-profile cached build
returned 101 on E0463 with mismatched dependency metadata. The successful Cargo
run then exposed a scratch controller's obsolete expectation of 229 tests;
that wrapper rejection is retained. The actual 236-test Cargo execution was
not repeated to repair the count: the same compiled test list was read and
matched to its returned transcript, followed by the missing Clippy command.

[retained-files.json](retained-files.json) lists every original file, byte
count and SHA256 and its retained representation. Large repeated metadata,
the cleanup inventory and the exact execution transcript are losslessly
compressed as `.gz`. Decompress them before comparing the original-byte hash;
no original observation was trimmed, relabelled or omitted by compression.

Later composed sources require their own appropriate checks or explicit
unchanged-input proof. This record does not certify later M06 edits and does
not convert the separate failed pretrained attempt into a successful one.
