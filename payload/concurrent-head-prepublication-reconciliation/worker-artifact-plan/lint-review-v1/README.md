# Worker artifact format and Clippy scope

This is a read-only supplement to the prepared worker unit-test plan. No format, Clippy, Cargo metadata, test or native command was run.

The selected N artifact is blob `f021a33e2969305241099998f703172d29b15251`. The captured M6 and N workspace/worker manifests and module entrances are identical. The new production `read_with_hooks` seam is reached by ordinary binary code; its two new controls and mutation helper are under `cfg(test)`. There are no added dependencies, features or lint suppressions.

The actual M6 `scripts/ci/ci_job.sh` lines 378 and 498 retain workspace formatting and strict workspace Clippy with all targets and all features. For the final merged source, preserve the original workspace format check. If the final full workspace strict Clippy is already planned, it covers this worker and no duplicate component run is needed. Otherwise, the minimal additional lint check is the worker package with `--all-targets --all-features -- -D warnings` on Linux, using the existing pinned toolchain and cache. A binary-only ordinary build does not lint the new test bodies, and a worker-only result is not a whole-workspace result.

Exact proposed argv and provenance are in `lint-review.json`. The full module unit run and both new validation-to-lock controls remain separately required. Nothing in this supplement establishes a test/lint pass, a Host result or the 4-second confirmation gate.
