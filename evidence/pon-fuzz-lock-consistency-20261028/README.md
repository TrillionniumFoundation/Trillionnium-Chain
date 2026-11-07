# Preserve the independently locked fuzz dependency graph

The original 131f fuzz and quality lanes stopped at `cargo fetch --locked`
because tests/fuzz/Cargo.lock lacked the current trnm-crypto-primitives and
trnm-pon-node path packages' zeroize dependency edges. The actual generated diff
adds those two entries only; no version, registry checksum, feature, manifest,
selector or default node graph was changed.

Retained observations: the first offline dry-run lacked libfuzzer-sys index
metadata (exit 101); a public index-only dry-run then succeeded with zero package
version updates. The actual offline workspace update succeeded. Locked offline
metadata succeeded. The first locked offline fetch failed because jobserver
0.1.35's source was absent. The subsequent locked online download succeeded with
an unchanged lockfile. Every command, return code and log is retained here.

This closes the locally reproduced lock-consistency error. No fuzz target,
native test, crypto operation, or account replay was executed. Advisory checks
were not reached by the original hosted quality lanes and are not claimed as
passed. Hosted execution of the new source remains separately qualified.
