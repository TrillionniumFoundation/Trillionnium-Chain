# Final worker artifact component executor — prepare only

The driver is prepared for root review; it has not been transferred to ROG or executed. Static validation parsed and compiled its AST without executing its module body or helpers. The exact final combined HEAD and tree remain mandatory invocation arguments.

## Fixed scope

The driver uses the existing source at /home/qian-qi/chain-final-consolidation-20261114-root/source and the already prepared Rust 1.95.0 toolchain and target cache. It does not fetch, import, checkout, install dependencies, or alter source/configuration.

After exact HEAD/tree/clean-status checks, it runs the original audit preflight and verify_ci_source before check. It verifies worker artifact Git blob f021a33e2969305241099998f703172d29b15251 plus its canonical single-link physical file, 12283 bytes and SHA256 12396ec45e2b059d588f7d00feb9f19cc557389e37be0053d9ff5f344825f3cc. This deliberately refuses the old worker on current ROG M6 until root has installed the approved final source.

It then performs exactly three component commands, using ordinary build/test semantics:

1. Original workspace cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check (180 seconds).
2. Worker cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-worker-agent --all-targets --all-features -- -D warnings (1200 seconds).
3. Worker cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-worker-agent --bin trnm-worker-agent audit::artifact::tests:: -- --nocapture (1200 seconds).

These are additional component budgets, not workflow or four-second confirmation limits. Toolchain versions are captured and required to be Rust/Cargo 1.95.0. Source/check stages retain the parent driver's 300-second ceiling; version probes use 60 seconds.

## Environment and outcomes

Reuse the existing owned Cargo target, CARGO_BUILD_JOBS=2 and CARGO_INCREMENTAL=0. The previous external driver fixed RUST_TEST_THREADS=1; this component clears inherited RUST_TEST_* variables to preserve default harness threading. Inherited Git/reference-selector names are cleared in the child environment and recorded without values. Nonempty compiler/profile/target overrides are refused, not silently changed. Existing Python/target/cache paths are used without installation.

The complete ten-name literal roster equals the previously sealed plan. The actual unit stdout must contain each full name exactly once with ok, running 10 tests, and one ten-passed/zero-failed/zero-ignored/zero-measured summary. The two validation_to_lock controls are mandatory. Unrelated tests filtered by the module selector are recorded separately. A list-only result, wrong binary, duplicate/missing outcome, failure, ignored control or ambiguous output cannot pass.

The original file-based capture and owned timeout handling are retained. Timeout sends SIGKILL only to the started child process group; if termination is not confirmed, the result is UNKNOWN. Each staged success/failure attempts verify-source-after in finally; acceptance requires its complete identity equal to source-before and the selected artifact unchanged. Complete stdout/stderr, argv, durations, independent budgets, process results, source sidecars, artifact sidecars and test-outcomes are retained in the new direct-child evidence directory. No automatic retry occurs.

## Future invocation, not executed

Use the existing ROG Python path and supply the actual reviewed values:

/home/qian-qi/chain-final-consolidation-20261114-root/final-python312-env/bin/python -B /home/qian-qi/chain-final-consolidation-20261114-root/run_final_rog_worker_artifact_existing_source_v1.py --head FINAL_HEAD --tree FINAL_TREE --evidence-dir /home/qian-qi/chain-final-consolidation-20261114-root/ROOT_CHOSEN_NEW_COMPONENT_DIRECTORY

The two SHA placeholders are not executable sample identities; the driver refuses them. Root must authorize transfer and execution separately.

This is an ordinary local Linux component run. It invokes no run_from_zero_host, Host controller/simulation, pressure workload or benchmark. It makes no hosted, public qualification or four-second/16-worker confirmation claim. A worker-package Clippy result is not a whole-workspace Clippy result.

## Provenance

The parent external existing-source v2 is preserved byte-for-byte, and external-v2-to-worker-v1.patch.original is the complete unified diff. static-review.json records the fixed roster/budget/argument checks. The producer is copied into this external review directory; EVIDENCE_INDEX.json and seal.json bind all closed preparation files. No stage prefix was changed.
