# Repair the isolated fuzz dependency graph

The [historical fuzz-smoke job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985420968/job/127144977223)
at source `6ee529046d295e3175f09112492abee373f1f54c` failed before any target ran:
`cargo fetch --locked --manifest-path tests/fuzz/Cargo.toml` refused its stale lock.
The [original artifact](historical-ci-failure.zip) is retained byte-for-byte; its
SHA-256 matches GitHub artifact 13410854312.

The same failure was reproduced on current parent
`a16a89f92a0db5ff6af9c1d7790f201841f079aa`. Only two missing dependency edges are
added to the isolated lock: `trnm-data-availability -> serde` and `serde_json`.
**All 147 package versions, sources and checksums are unchanged.** Neither the
normal native lock nor the fuzz toolchain, target code, seeds or command changes.

The CI contract now checks unconditional, nonoptional normal dependencies of
local native workspace members against their fuzz lock entries, including package
aliases and workspace inheritance. It intentionally does not infer dev, optional
or target-specific edges; Cargo remains the authoritative complete graph check.
Negative controls remove each missing serialization edge. Existing version guards
remain. Contract suite: **100 passed**; source-negative suite: **37 passed**.

## Actual execution and retained failure

[Red current fetch](current-fetch-before.txt), [repaired stable fetch](current-fetch-after.txt),
and [original pinned-nightly fetch](nightly-fetch-after.txt) retain actual output.
Initial offline resolution also reported unavailable `arbitrary v1.4.2`; normal
locked fetch subsequently downloaded the missing packages without changing the
repaired lock. No unlocked fetch is used by the production CI command.

Frozen fix `e6e64acd39ecb450d3ef6b3d1136fb86a523f5c5` was run with the **unchanged**
`python3 scripts/ci/run_fuzz_smoke.py` default full selection. Rust
`nightly-2026-10-01`, cargo-fuzz 0.13.2, ASan, debug assertions, seed 20261004,
60 seconds per target, 10-second per-input timeout, 2,048 MiB RSS and 1,200-second
command limits were preserved. Tool installation used the original pinned script.

The lock and first target build succeeded. `canonical_wire` executed
**17,068,443 mutations in 61 reported seconds**, final edge coverage 303 and peak
RSS 458 MiB. Then LeakSanitizer terminated with its ptrace-unavailable fatal error;
the target and wrapper returned **FAIL**, and the other two targets were **NOT_RUN**.
The emitted crash artifact is the empty input, not evidence establishing a parser
bug. No sanitizer was disabled, security setting changed, timeout enlarged or
failure relabeled as success.

[Complete local failed receipt](current-original-fuzz-failure.zip) retains every
log, corpus entry, empty crash artifact and manifest. All declared artifact hashes
were checked before packaging. [Verification](verification.json) binds both source
identities, archives, unchanged limits and actual process returns. Mutation counts
do not constitute a passing sanitizer run or qualification.

The dependency blocker is fixed and protected by a regression check. **Full
hosted fuzz-smoke remains open** until the original three-target gate completes on
an appropriate runner. No existing business, PQ, release or activation gate is
promoted. Historical and local failures retain their exact source scope.

## Reproduce

```
bash scripts/project-preflight.sh
cargo +nightly-2026-10-01 fetch --locked --manifest-path tests/fuzz/Cargo.toml
python3 scripts/ci/check_ci_contract.py
python3 scripts/ci/test_ci_contract.py
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/refresh_distributed_source_inventory.py --check
bash scripts/ci/install_ci_tools.sh fuzz
python3 scripts/ci/run_fuzz_smoke.py
```

Use a fresh receipt directory for each full run. The full command stops on a
failure by design. [Contract output](contract-tests.txt) and
[source controls](source-tests.txt) are static/control results, not native fuzz
success. The unchanged native workspace also passed strict all-target/all-feature
Clippy on the repaired tree; see [log](workspace-clippy.txt).
