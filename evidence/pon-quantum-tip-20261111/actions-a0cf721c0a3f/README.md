# Final candidate focused Actions: observed completion

Candidate `a0cf721c0a3fd5bc034e010119d2b09d148de8ec`, tree `0fee4598d69db92beea2845c6d939f059f2d14a3`.

[Run 42942301962](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942301962) completed both focused jobs successfully. This directory preserves their original complete retrieved job logs, without replacing prior failures.

- [Quantum job raw log](quantum-tip-paired.log): ten suites report 58 + 12 + 18 + 34 + 28 + 58 + 19 + 19 + 5 + 180 = **431 passing tests**. The qualification request actually returned exit 3 and `REFUSED_UNPROVED_JOINT_CONSENSUS`. All 72 observations reached their full horizon, all 36 pairs were present, and all 72 traces replayed. The current W1 survey was independently recomputed by its retained nineteen-test suite.
- [Native job raw log](native-current-clock.log): the single library selection ran **6 passed / 0 failed / 0 ignored**, with 1326 filtered out. Both named current-clock regressions ran, the nonempty-selection guard passed, and `cargo fmt --all -- --check` passed.
- [Structured observation](execution-summary.json): exact raw-log hashes, suite counts, source identities, job step metadata, artifact identities, and explicit qualification limits.

Each lane verified the complete tracked source before and after: **27,930 entries / 2,555,806,765 bytes**, the exact candidate commit and tree, and `tracked_worktree_verified=true`. A source identity check itself does not execute tests; the separate test outputs above do.

The Actions ZIP artifacts remain governed by their own external retention. This directory archives the complete job logs, not those binary archives. The [desktop Python archive](../desktop-a0cf721c/python/README.md) independently preserves all 72 gzip traces, every command's raw output and receipts, source snapshots, and a member-hashed ZIP.

These are focused observations. They do not establish complete required-baseline success, a mid-W1 clock rollback race result, a native W1 quantum cost lower bound, CP/CG/CQ, or production qualification. All qualification flags remain false or unknown; status remains **HOLD / NO-GO**.
