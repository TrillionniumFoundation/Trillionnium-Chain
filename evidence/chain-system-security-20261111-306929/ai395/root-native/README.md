# Root native observations on the combined bac6 source

Status: **HOLD**. Production activation remains false. This directory preserves
two completed native execution stages and the full workspace strict Clippy
result for exactly
`bac6b7659bd7e2d633e25c2da0add60f6a10c7fb`, tree
`371c3f55de7940e276496efe2008b537ba4d8268`.

The observed worktree contained **28,327 tracked entries and 2,578,801,275
tracked bytes**. The original complete source checks before and after the
commands agreed. The five pinned provider inputs also agreed before and after
both stages. Later evidence or metadata commits do not inherit this exact-HEAD
native qualification.

## Actual execution and counting

| Execution stage | Native target | Methods | Actual result |
| --- | --- | ---: | --- |
| Original V5 runner | Fresh witness | 17 | Passed, no filtered or ignored methods |
| Original V5 runner | Durable witness | 12 | Passed, no filtered or ignored methods |
| Original V5 runner | Witnessed provider readback | 8 | Passed, no filtered or ignored methods |
| First selected V4 command | Provider readback only | 14 | Passed; selected-target observation |
| Complete original V4 runner | Recovery floor | 9 | Passed |
| Complete original V4 runner | Provider readback | 14 | Passed; these methods repeat the selected target |
| Complete original V4 runner | Callback budget | 6 | Passed |

There were **80 method executions, 14 repeated methods, and 66 unique methods**.
The 14 repeated provider methods are not additional coverage. Every completed
native target had zero failed, ignored and filtered methods, with its exact
reviewed method inventory checked against the raw libtest output.

The first launcher used the original V5 runner, followed by the selected V4
provider Cargo target and the original provider inventory checker. Its raw
summary field `v4_complete_inventory_passed` means the selected
`PROVIDER` inventory of **14** methods. It does **not** mean the complete V4
runner or its three-target execution contract. That selected command did not
enforce the V4 runner's outer 1200-second timeout. Its original summary and logs
are retained unchanged, and the later result is not used to rewrite its scope.

The second stage executed the unmodified
`scripts/ci/run_pq_root_continuation_v4.py` through the original complete-source
command recorder. It retained all 29 reviewed methods, the original features
and profiles, and the original **1200-second timeout for each target**.
Its recovery-floor, provider-readback and callback-budget commands exited 0 in
209.622, 996.955 and 13.339 seconds respectively. The original V4 runner and its
outer recorder both exited 0. Their recorded overall elapsed time includes all
three targets and source checks; it is not a single-target timeout.

The first stage also completed this exact strict gate with exit 0:

```text
cargo clippy --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The actual `cargo clippy`, `cargo-clippy` and `clippy-driver` version probes
reported Clippy 0.1.95 from the absolute Rust 1.95 toolchain. No profile,
feature, warning threshold, wrapper or compiler flag was relaxed. The separate
SQLite package checks have their own receipts and are not counted here.

## Included records and replay

[manifest.json](manifest.json) identifies the exact compressed archives,
actual launchers, source, provider and counting rules:

- [root-native-original-observations.tar.gz](root-native-original-observations.tar.gz)
  retains the first stage: 39 original observation files, its actual launcher,
  and its member manifest.
- [root-v4-full-original-observations.tar.gz](root-v4-full-original-observations.tar.gz)
  retains the complete original V4 stage: 16 original observation files, its
  actual launcher, and its member manifest.
- [verification.json](verification.json) is an archive-only revalidation.
  [verify_archives.py](verify_archives.py) can reproduce it using Python's
  standard library:

```sh
python3 evidence/chain-system-security-20261111-306929/ai395/root-native/verify_archives.py
```

The validator checks the archive and member hashes, raw log bindings, exact
native names and result lines, whole-worktree source receipts, provider receipt
agreement, the strict Clippy command and the full V4 runner command. It computes
the repeated and unique method sets directly. It reads the tar streams without
extracting them and keeps the existing 4 MiB file/member cap. It executes no
Rust tests, Clippy, provider build or external effects.

Both raw owner output archives and their terminal observations are retained
alongside the compressed records. The original failed or interrupted cloud
observations in
[the b7 evidence](../../../pq-root-witness-provider-readback-20261112/README.md)
remain unchanged: those two attempts executed no Rust libtest case. These
later successful observations belong to the combined bac6 source and the
separately prepared AI395 provider. They do not fill in the earlier attempts'
missing source-after receipts or establish the cause of their SIGKILL reports.

## Toolchain and provider boundary

The native commands used the explicit Rust 1.95 compiler and its canonical
toolchain library directory, one Cargo build job and one libtest thread.
The separately prepared OpenSSL 3.5.9 CLI was pinned to SHA256
`09362cd9a4f5ef29e9cdd9fe26092a706ffe589f1e52c8c5572bd74df7ccdc1d`.
The provider preparation receipt was pinned to
`509219f0ebd60c563342a509a9751a98222b44890a28552c8003e751924a9eeb`.
Both native stages rehashed all five recorded provider inputs before and after
execution. The archive validator only rechecks the included receipts and bytes;
it does not rebuild or independently run that provider.

The actual native ELF files were preserved on AI395 outside the shared Cargo
target. The selected/full provider target had the same recorded ELF hash and
uses the same preserved copy. Six distinct test ELF files are retained; the
large executable files are not placed in these small archives. Their identities
and preservation locations are in the archive-result records.
**Those hashes and copies were recorded after execution. They are not live
inode or loader attestations.**

## Implemented scope and remaining limits

The new
[readback bridge](../../../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5/provider_readback.rs)
requires fresh authenticated V5 context around the historical provider identity
lookup and on both sides of the provider callback. It preserves the original
operation and material, checks known key-role separation and budget identity,
and fences failures. The
[eight new native methods](../../../../trillionnium/crates/trnm-pon-node/tests/root_witness_provider_v5_native.rs)
cover cold owners, lost replies, unknown outcomes, witness failure/regression,
cross-role keys, callback budget/cancellation changes and exact historical
identity.

A fresh read challenge can be used to query the same operation. It does not
authorize a second payment or another effect attempt. Pending survives a lost
read reply, and Unknown does not erase a known Applied outcome or grant
redispatch permission. Signed provider outcomes remain provider declarations.

V5 constrains Root identity and freshness within the tested trust boundary.
**It does not bind every provider journal head to the witness.** A cold rollback
of that separate journal, or loss of provider history, still requires external
reconciliation of the same operation. The live-session rollback controls do not
establish a general cold-recovery guarantee.

The passing common-restore contrasts retain the distinction between a surviving
external freshness pin rejecting old state and restoring every authority
accepting old state. Different algorithm/key identities do not establish
different administrators, machines, backups or recovery rights. These fixtures
use real PQ signatures and SQLite/files with an in-process witness; they do not
prove independently surviving custody, new recovery entropy, a production
witness daemon/wire codec, ordinary M15 assembly or real external-effect truth.
All corresponding qualification and activation flags remain false.
