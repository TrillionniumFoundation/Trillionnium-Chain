# Independent historical harness lock for CodeQL scanning

This is new scan preparation on 2026-11-07. It is not a reconstruction of the
original W1 measurement or its missing source tree, and executes no historical
native harness. The production workspace and its locked dependency graph are
unchanged.

The concurrent PR #688 head `3d1b6507671ec694ce58e86d4063a125c8deeb66`
retained the exact head and prospective-merge CodeQL failure scene. Both Rust
artifacts contained one untracked path:
`evidence/pon-w1-work-security-20261101/matching-direct-deps/harness/crypto/Cargo.lock`.
Their tracked diff-name and diff-stat records were empty. The source guard
correctly refused the changed worktree; the
[raw diagnosis](../acceptance/concurrent-3d1b/README.md) retains both ZIPs and
source identities. The earlier `271a87f...` artifact did not retain a dirty-path
inventory, so this later diagnosis is not retroactively assigned to that run.

The crypto package has its own manifest and no Cargo workspace membership.
Its parent's retained lock therefore does not provide a lock for independent
scanning. The added crypto lock was seeded from the unchanged parent lock and
normalized by Cargo 1.95.0 with full offline metadata. Its 12-package dependency
closure, versions, checksums and dependency edges match the parent lock exactly.
Two subsequent full `cargo metadata --offline --locked` calls succeeded without
changing it. All six historical files checked in
[preparation.json](preparation.json), including the original measurement
manifest, remain byte-identical. The original `harness_before`/`harness_after`
records are unchanged. The existing historical index adds a separate
`subsequent-codeql-scan-lock-preparation-20261107` entry with
`original_capture_artifact: false`.

The complete metadata stdout/stderr and command records are retained here.
This change keeps the full scan and strict source-before/source-after checks.
It adds no cleanup step, ignore exception or reconstructed Rust module.
Successful local metadata validation does not qualify the new hosted CodeQL
scan, the historical W1 experiment, original-resource service acceptance or
production activation.
