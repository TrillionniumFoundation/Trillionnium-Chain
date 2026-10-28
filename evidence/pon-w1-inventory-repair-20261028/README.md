# Native source inventory follow-up after the exact-source hosted failure

The actual [focused native run 40611562732](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40611562732)
on #525 head `febf622c7e4e919ad2ee4e0864230ab572f5d5b4`, tree
`f936a01b1391242c2014b162ea2d77ef18769e67`, passed the full repository checker
with 1,336 local links and 1,016 Rust files. Source-before/source-after both
verified all 6,479 tracked entries and 772,148,228 bytes. The next mandatory
check failed because the embedded distributed native source inventory had
not yet included the two new W1 helper/policy files. This failed run is retained
as a failure, not replaced by the later local repair.

The official inventory generator reproduced the failure locally with exit 1.
Running the unchanged generator adds exactly two include entries, fourteen
Rust lines: `host/src/bin/check_frozen_receipts.rs` and
`segment-continuation-v2.json`. No existing entry is removed. Its next `--check`
and formatting both passed. The original 30 W1 source pins, guest, SDK/lockfile,
helper source, mathematical relation and all proof budgets stay unchanged.
No native compiler or local prover ran for this metadata repair.

The complete hosted log, before/refresh/after commands, exit codes, measured
wall times and exact generated diff are retained here. The new source still
requires its own hosted validation; this local inventory pass does not claim a
native integration pass or completed W1 proof. The separate a54 continuation
and febf strict native-gate runs continue under their own exact source identities
and costs. This follow-up does not cancel them or merge their observations.

Publication controls also passed the CI contract and 34 source-integrity
negative cases. The local whole-repository checker remains blocked by the
intentionally unmaterialized historical `evidence/pon-v1/README.md` in this
sparse checkout; its exit 2 and raw message are retained. This is not rewritten
as a pass or silently repaired with replacement historical evidence. Changed
Markdown targets are checked against actual local files or the retained full
Git tree. Hosted complete-checkout verification remains necessary.
