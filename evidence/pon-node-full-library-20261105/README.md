# Complete Node library observation (HOLD)

The original default-feature Node library command on clean source `7ae0d1b227853fc75e02334b497f69dd52d50235` completed with **1,074 passed, four failed, 28 existing ignored, zero filtered**, exit 101, in 856.13 seconds. This is a failed full invocation, not qualification. The two original 65,536-key continuity/growth and capacity-refund/reorganization tests both passed.

[Exact inputs and hashes](verification.json) and [complete raw output](raw-logs.zip) retain the original failures. The delivery parent changes only supply-chain evidence relative to the tested source; it does not turn this into a new native run.

The kernel CPU-stat test fails reading `/sys/fs/cgroup/cpu.stat` with ENOENT. Three guarded NPQ6 submit/replay/restart tests fail before the independent witness becomes ready: `UnixListener::bind(witness.sock)` returns EPERM. Separate diagnostic invocations reproduce that same failure for each of the three selectors. Their outputs are retained separately and are not added to the full-suite denominator. The valid-only diagnostic shell printed its captured log after execution; its final shell exit was zero, but the native result in that log is FAILED.

No test, ignore, assertion, deadline, feature, Host check or sandbox permission was changed to mask these failures. No PQ-native provider, hosted business gate, independent operation or complete workspace execution is claimed. The full log includes nested child results; only its final outer summary defines the reported denominator.

Reproduce with Rust 1.95.0, the repository profiles and locked graph:

`CARGO_BUILD_JOBS=1 cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --locked -p trnm-pon-node --lib`

The original feature selection is default. Run the environment-dependent controls on a normally provisioned qualifying host, without relaxing their checks.
