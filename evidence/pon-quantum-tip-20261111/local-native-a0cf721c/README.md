# Final candidate: independent desktop native observations

Candidate `a0cf721c0a3fd5bc034e010119d2b09d148de8ec`, tree `0fee4598d69db92beea2845c6d939f059f2d14a3`.

The [complete original receipt](receipt.json) records status **PASSED**, no failures, and actual exit zero for all eight commands. The [native raw log](native-current-clock.log) shows one library target with **6 passed / 0 failed / 0 ignored**, 1326 filtered out, and 4.35 seconds of test execution after compilation. Both required regressions are present:

- `public_growth_v1_future_ancestor_defers_fresh_and_duplicate_before_work`
- `public_growth_v1_rechecks_future_ancestry_before_new_and_duplicate_activation`

The native command used the repository's locked dependency graph and normal test profile:
`cargo test --locked --lib -p trnm-pon-node public_growth_v1 -- --nocapture`.
The recorded command duration was about 732.65 seconds, including compilation.
The separate whole-workspace `cargo fmt --all -- --check` returned zero.

The source checks before and after are byte-identical: **27,930 tracked entries / 2,555,806,765 bytes**, exact candidate commit and tree, and complete tracked-worktree verification. Git status was clean before and after. The Cargo manifest and lockfile were unchanged, and Cargo profiles were not altered. The old task-owned target directory was reused after its original driver had finished; this is not a from-zero build claim.

## Complete original evidence

- [Archive manifest](archive-manifest.json) gives every original file's size, SHA-256 and Git blob.
- [Original driver](driver.py) and [execution manifest](manifest.json) preserve commands, validation and source bindings.
- [Native evidence archive](native-evidence.tar.gz) contains all fourteen original files plus the archive manifest, fifteen regular members in total. Every member was reopened and compared with its original bytes.
- [Blob map](blob-map.json) records the published objects and byte-for-byte readback verification.

Archive size is 7,539 bytes; SHA-256 is `0b7b47fc51d7cc2d1f5643fef7c754ff493a08fead7ce62cf9de0a6ffaa0b00a`.
The original receipt SHA-256 is `34eb91f24fed9c94aa1492badfe41dca669b791615501bfdf96710a8fd3cee06`.

A final supervisor-status query encountered a tool transport error. Completion here is established by the complete original driver receipt, actual subprocess exits, full raw logs and source-after check, subsequently read through the file interface. No additional supervisor exit code is inferred from that failed query.

These results are separate from the [same-candidate Actions results](../actions-a0cf721c0a3f/README.md) and the [historical precommit negative baseline](../recovered-native-precommit-e4abb172/README.md). The fixture does not directly inject wall-clock rollback during unlocked W1 and owner reacquisition, nor prove scale or hostile-load liveness. CP/CG/CQ, quantum and production qualification remain **HOLD / NO-GO**.
