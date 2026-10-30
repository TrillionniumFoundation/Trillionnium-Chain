# risc0-zkvm-platform 2.2.3: maintained source adoption

The complete published archive has SHA-256 `2eb37a97ff7e8e4ee1b2a1c43ec143b4887759883c343507af9e4787a57914cd`.
`UPSTREAM.json` records every original member and its immutable hash. The
original package name, version, license, features, Rust sources, unit tests and
test data are retained. `Cargo.toml.orig` is original provenance, not the active
maintained manifest.

The active maintenance is to keep the original paste source alias and resolve the real maintained pastey package at =0.2.3.
The package is marked non-publishable and has M01 ownership metadata. The primary
workspace uses a same-name patch and inventories the complete source under M01.
Lock resolution and native verification require their own actual observations. No registry cache source is edited, fake package is introduced, or proof
feature is removed. Original package-local locks remain upstream provenance.

The initial import had no native acceptance. Prior local G observations were lost
in workspace maintenance and are not reused as current evidence. Fresh H0–H5
compilation, original suites, documentation tests, strict lint, feature unions
and consumer checks are recorded below and in `UPSTREAM.json`.
A host build is not guest syscall functional verification. No supply-chain,
public-fairness, consensus, post-quantum or production qualification follows.

The archive did not contain a standalone license file. `LICENSE` is an explicitly supplemental copy from the exact upstream Git commit recorded by the archive, with its URL, Git blob and SHA-256 bound separately. It is not represented as an original archive member.

The source adoption base is `c96c2b3e24ba354b4abcb842ca6a6a019c442b73`. The separate W1 guest workspace is unchanged. The initial adoption preserved the original Rust sources and test data. Subsequent maintenance is recorded separately, including every modified original member and failed observation.

## Final H5 native observation

Actual execution used local commit `c7cf03f18e0985ba5c542bf756eaa9189ab73a97`, tree `8a5663d8f866372c1a59b587f18fa70b96d45ea9`. The [GitHub source commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2c1898d239b6f5565e3ac681e4274e8e88f42403) has the identical complete tree; commit metadata differs. [Lossless execution records](../../../evidence/pon-owned-parent-native-c7cf03f1-20261030/README.md) preserve the original failures, command output, source observations, binary hashes and readers.

The maintained package passed 0 library tests and 1 documentation tests, with no ignored or filtered cases, and its no-default library check. The published package has zero original unit tests; that result is not guest syscall verification. The six-package union build, all six library suites and both existing consumer integration suites (5 and 4 tests) passed. Seventeen test-disabled examples were compiled only. The original consumer helper ignore remained declared and was exercised by its parent test; no new ignore was added. Whole-workspace release/all-target/all-feature strict Clippy and formatting passed on that exact H5 source.

These are scoped host observations. The standalone W1 workspace, remaining SDK/Apple dependency paths, complete proof production, public fairness and whole-chain post-quantum qualification remain open. This later documentation update does not relabel an H5 execution as a test of a different tree.
