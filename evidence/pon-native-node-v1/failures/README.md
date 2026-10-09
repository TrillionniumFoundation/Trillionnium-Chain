# Retained preparation failure

The first dirty-worktree native test attempt used the default Cargo cache and could
not resolve the locked ahash 0.8.12 archive offline. No native test ran in that attempt.
The original raw diagnostic is unchanged. The subsequent isolated cached Cargo home
used the same locked dependencies; no assertion, package version or timeout was weakened.
This is an environment preparation observation, not a clean-source runtime failure.
Earlier recovered development records remain untouched in their original owned directory.

The first owner-lock patch hit Rust E0308 at a temporary MutexGuard expression.
The guard binding was corrected and the actual full clean-source qualification was
executed afterwards. The original compiler diagnostic is retained, not a runtime pass.

The first staged publication whitespace check reported trailing bytes in original Rust
test output. The bytes were preserved unchanged and the existing raw-evidence attribute
policy was extended only to this new receipt path. Source formatting was not waived.
