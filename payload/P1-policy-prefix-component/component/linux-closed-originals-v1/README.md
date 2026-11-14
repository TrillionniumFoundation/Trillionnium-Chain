# Closed Linux component validation originals

This newly assembled ZIP contains exactly 115 original files (398,878 uncompressed bytes): 112 files from the two completed validation directories and three complete actual terminal transcripts. Member names have the fixed originals/ prefix. The index records each exact zip_member, original ROG origin, immutable-read version, size, and SHA256. Every member's CRC and SHA256 was verified after ZIP creation.

The first validation used RUST_TEST_THREADS=1: three prefix controls, one original golden control, and strict all-target/all-feature Clippy passed. It is a serial harness record. A separate follow-up removed inherited RUST_TEST_* variables and repeated only the same three plus one tests with the default harness; all four passed with zero ignored. Clippy was not repeated. The original compiler-path warning and both original environment records remain unchanged.

These results describe M8 plus the exact one-file uncommitted proposal at that time. They do not claim that the proposal was a clean M8 checkout, that the current root worktree is still M8, or that hosted 4-second performance or SQLite native qualification passed. This packaging operation reads only closed evidence; it runs no tests, Git, source reads, or network operations.

The official transfer provenance retains the source versions, pinned chunks, upload acknowledgements and final destination checks. Provider bookkeeping files are explicitly excluded, not validation outputs. Executed programs are preserved separately as exact code strings from the actual terminal invocations, clearly saved after execution. The original Mac compilation failure and all other component failures remain elsewhere in the component evidence.
