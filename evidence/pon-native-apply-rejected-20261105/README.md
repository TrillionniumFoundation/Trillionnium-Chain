# Native apply cache experiment: rejected default integration

The fixed first campaign rejects enabling this optimization. All eight cells preserve full roots, stored rows, actual SQL counts, callback counts and rollback. Six timing cells pass, but two cold sparse cells fail the criterion fixed before execution. The default implementation is restored; the rejected candidate remains only under `cfg(test)` for reproducibility. No Host, confirmation, security or product gate is closed.

## Source and execution

The measured candidate is local commit `d685a14ac2b2ce0a30e7bacee6eb29290d8248cf`, tree `88ddb8b5d9c3a4885ed00a69804700c02cf44a65`, based on `f9977c5d6d1b57880967ef36dcd1570010cbbe4f`. Its complete patch is retained in the raw archive. Original Rust 1.95.0 profiles and locked packages were used, with one build job. The test-only rusqlite trace feature adds no package and is absent from normal production dependencies.

The measured source passed eight new native differential/adversarial tests in both test and release profiles, plus three existing real publication/cancellation/reopen tests in the test profile. The first attempted test observer failed the project's unsafe-code prohibition; its full compiler error is retained. The observer was corrected to the dependency's safe trace API, without weakening that prohibition. The first CI-contract check exposed stale inline source hashes; the exact hashes were corrected without changing the gates.

Final isolation source `1a7357936942e0e8a3564026e5257dc95cba6ea4` restores `native_authenticated.rs` and the existing batch test file byte-for-byte to the base. `native_store.rs` differs only by its test-module declaration. An independent code review found the relocated candidate algorithm unchanged apart from module qualification, visibility, comments and formatting. It is not a production fallback.

## Fixed complete-apply campaign

There are 512/1,024 accounts, one or one-quarter changed accounts, and cold or parent-graph-warmed arithmetic caches: eight cells, twelve alternating pairs each, three arms per pair. All 288 samples, 96 pair records, eight cell records and the final false qualification summary are retained. The original function, candidate and uncached fallback execute in one release test binary.

Each timed interval includes complete apply through returned-root disposal. Transaction begin/rollback, parent-cache warming, cache setup/destruction and post-call inspection are outside that interval. The SQL database is in memory; SQLite page/statement caches are not declared cold. Actual SQL counters come from a separate identical-input equivalence replay, not the primary timing interval. These observations cannot establish complete publish, disk, network, scheduling, hostile-W1 or confirmation cost.

The preregistered component criterion requires at least 5% median improvement and no more than 10% p95 regression in every cell, alongside complete equivalence. With twelve values, nearest-rank p95 is the maximum. The failed cells are:

- 512 accounts, one change, cold cache: median ratio **6.394383**, p95 ratio **26.703932** against the original.
- 1,024 accounts, one change, cold cache: median ratio **0.976192**, only 2.38% improvement, below the required 5%; p95 ratio **0.649718**.

Warm and dense gains do not cancel those failures. No sample was removed, no repeated campaign selected, and no threshold changed. A successful test process exit reports completion, not performance acceptance. The independent projection recomputes all eight medians/p95 ratios from the complete raw roster and confirms rejection. Its reader accounts for the first sample sharing the Rust harness test-name line.

## Reproduction and limits

Use the final test-only fixture with the original locked release profile:

`cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib native_apply_reader_paired_complete_apply_cost_observation -- --ignored --nocapture --test-threads=1`

The retained campaign was run once on the measured candidate, not again on the isolated delivery. Re-running is a new observation, not a replacement for these failures. [Exact records and hashes](verification.json) bind the raw archive and validation logs. Production defaults, Growth bounds, every actual SQL read, progress callback, error ordering and original business gates remain unchanged.

Final test-only revalidation passed eight native controls (one explicit cost fixture ignored), formatting, strict workspace/all-target/all-feature Clippy, 37 source controls, 100 CI-contract controls, all 522 source pins and generated inventory. The locked graph remains 26 workspace members and 175 packages. These results do not promote the rejected performance decision.
