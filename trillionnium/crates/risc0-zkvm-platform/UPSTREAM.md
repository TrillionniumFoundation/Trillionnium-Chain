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

This preparation has no native acceptance. Prior local G observations were lost
in workspace maintenance and are not reused as current evidence. The restored
source requires fresh all-target/all-feature compilation, all original unit and
documentation tests, strict lint, relevant feature unions and consumer checks.
A host build is not guest syscall functional verification. No supply-chain,
public-fairness, consensus, post-quantum or production qualification follows.

The archive did not contain a standalone license file. `LICENSE` is an explicitly supplemental copy from the exact upstream Git commit recorded by the archive, with its URL, Git blob and SHA-256 bound separately. It is not represented as an original archive member.

The source adoption base is `c96c2b3e24ba354b4abcb842ca6a6a019c442b73`. The separate W1 guest workspace is unchanged. This initial adoption preserves the original Rust sources and test data; later test-oracle or lint maintenance must be recorded independently.
