# Portable SQLite sidecar opening boundary

This is a candidate storage boundary repair on C5. Production activation remains
disabled. It does not qualify the complete chain or establish a remote SQLite
exploit. The five changed openers already promised to refuse unresolved SQLite
sidecars; this change makes that existing local contract hold for dangling links,
non-UTF-8 database names and sidecar metadata errors.

## Source identities

| Role | Exact commit |
| --- | --- |
| C5 base, PR #908 | `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d` |
| Initial DA tests, old runtime | `52cf278e4c3d08931b3e890c26b2b1af5653d32d` |
| Tests for the other owners, old runtime | `857d661de6265459d4af3323f4000c2c04fb90e1` |
| Fixed runtime used for positive native observations | `9021d15ffe1dfdfb1358a2372b5a472babbf80ac` |

The test-only commits are ancestors of the fixed runtime. The evidence commit
adds records; it must not be substituted for the actual native tested commit.
Integration must preserve these identities when merging this work.

## Dependency and CI readback

The immutable-head lockfiles and GitHub Actions statuses were read again at
2026-11-12 00:13 UTC. The complete normalized readback is in
[remote-dependency-ci-readback.json](remote-dependency-ci-readback.json).

| Source | `libsqlite3-sys` | `rusqlite` | `rustix` |
| --- | --- | --- | --- |
| [main at dd6e1c3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dd6e1c3cbeacbdc532b0679297835b3a0aac78f0/trillionnium/Cargo.lock) | 0.30.1 | 0.32.1 | 1.1.4 |
| [#900 at 64e540a](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/64e540ad4603aaf5a2677bd080995fc4ef296bbb/trillionnium/Cargo.lock) | 0.39.1 | 0.41.1 | 1.1.4 |
| [#901 at 6c35f94](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/6c35f94d9387fac41c1547f05742d70150320b2e/trillionnium/Cargo.lock) | 0.39.0 | 0.41.0 | 1.1.4 |
| [#908 at 6ac9a79](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d/trillionnium/Cargo.lock) | 0.39.0 | 0.41.0 | 1.1.6 |

[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html)
identifies uninitialized memory exposure when vulnerable bundled SQLite opens an
attacker-controlled local database with a mismatched sibling WAL. The advisory
patch threshold is `libsqlite3-sys >= 0.39.0`. The base already meets that threshold.
No memory-exposure exploit was reproduced in this work. This patch repairs
portable-store opening contracts and does not change the dependency graph.

The actual locked local graph resolves one `libsqlite3-sys 0.39.0` with `bundled`
enabled and one `rustix 1.1.6`. The cached amalgamation declares SQLite 3.54.0.
The source ID, amalgamation hash, dependency features and Cargo metadata hash are
recorded in [dependency-graph-readback.json](dependency-graph-readback.json).

PR #900's original exact-head quality archive remains a failed observation.
The readback verified the ZIP CRCs, 14 unique members and all eight payload hashes
in its original supply-chain manifest. Its workspace policy diagnostic is
`RUSTSEC-2026-0486` for `rustix 1.1.4`; it does not report SQLite advisory 0459.
The original workspace policy exit is 1 and the fuzz policy exit is 0. See
[the original archive](sqlite900-quality-13843531543.zip),
[its independent readback](sqlite900-quality-independent-readback.json),
[the exact-head CI run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42989235807),
and [the official rustix advisory](https://rustsec.org/advisories/RUSTSEC-2026-0486.html).
This was archive verification, not a new GitHub run or an independent full source
scan. C5 already updates rustix to 1.1.6.

The queried Actions run totals were: main 5 success; #900 18 success and 5 failure;
#901 20 success and 5 failure; #908 16 success and 8 failure. These totals are
status readbacks, not release acceptance. In #908's required-baseline run the
head and prospective Rust runtime/quality shards and their Rust aggregates were
successful, while the overall workflow still failed. Candidate fixes remain
unmerged and cannot be credited to main.

## Runtime changes

Only the existing `reject_sidecars` functions of these owners change:

| Owner | Previous gap | Fixed behavior |
| --- | --- | --- |
| DA store | `display()` changed non-UTF-8 path bytes; `exists()` followed dangling links and hid metadata errors | Preserve the `OsString`; inspect the directory entry with `symlink_metadata` |
| MVCC fee store | `exists()` treated dangling links and metadata errors as absent | Inspect the entry without following its final symlink |
| Consumption settlement store | Same `exists()` behavior | Same strict entry inspection |
| Task market store | Same `exists()` behavior | Same strict entry inspection |
| Task archive store | `symlink_metadata(...).is_ok()` hid errors other than absence | Distinguish `NotFound` from all other errors |

Every present entry retains the owner's existing sidecar error. Only
`ErrorKind::NotFound` permits opening to continue. Every other inspection error
returns the owner's existing `StoreFailure` error before SQLite is opened.
No schema, signed domain, reward rule, dependency or production switch changes.
The legitimate WAL protocols owned by other stores are not converted into
no-sidecar stores.

## Native negative and positive observations

All commands used the existing locked graph, native x86_64 Linux and Rust 1.95.0,
with default Cargo profiles and two build jobs. No assertion was ignored and no
test threshold, feature or lint policy was reduced. Tool executable versions and
hashes are in [toolchain.json](toolchain.json).

The filtered Cargo command for each package was:

```text
cargo test --locked --offline -p PACKAGE --lib sqlite_ -- --nocapture --test-threads=1
```

| Observation | Source | Passed | Failed | Ignored | Native exit |
| --- | --- | ---: | ---: | ---: | ---: |
| DA old runtime | `52cf278e` | 4 | 3 | 0 | 101 |
| MVCC old runtime | `857d661d` | 1 | 2 | 0 | 101 |
| Settlement old runtime | `857d661d` | 0 | 2 | 0 | 101 |
| Task / archive old runtime | `857d661d` | 1 | 3 | 0 | 101 |
| DA fixed runtime | `9021d15f` | 8 | 0 | 0 | 0 |
| MVCC fixed runtime | `9021d15f` | 3 | 0 | 0 | 0 |
| Settlement fixed runtime | `9021d15f` | 2 | 0 | 0 | 0 |
| Task / archive fixed runtime | `9021d15f` | 4 | 0 | 0 | 0 |

The old-runtime exits of 101 are preserved as failures. They are not relabeled as
successful native runs. The ten newly failing crate/test pairs subsequently pass
at the fixed runtime. The initial DA failures show the public opener returning a
store where sidecar refusal is required. The metadata-error tests exercise real
`ENAMETOOLONG` from a valid 255-byte database basename with an appended SQLite
suffix; they do not depend on running as a non-root user or mock filesystem APIs.

There are 12 new crate/test pairs in total. One archive sidecar compatibility
test already passed with the old runtime. The additional DA metadata-error test
was introduced after the initial DA negative run and was only executed on the
fixed runtime; it is not counted as an old-runtime failure.

The fixed tests cover absent and existing databases, the `-wal`, `-shm` and
`-journal` entries, real sidecar files and dangling links, non-UTF-8 DA path bytes,
and metadata errors. They check refusal before main database creation, unchanged
existing database/sidecar bytes, unchanged symlink targets, and successful normal
creation/reopening after the interfering sidecar is removed. Assertions apply to
the tested filesystem states; they do not establish race-free path ownership.

In addition, 15 existing native compatibility tests pass using the exact hashed
ELFs from the fixed builds, without recompiling or changing source. These cover
schema and row tampering, existing-store regular-file requirements, crash and
commit uncertainty reopening to the exact source/target or a permanent fence,
archive proof preservation, and long-name/concurrent archive initialization.
All 15 selected names execute exactly once, with zero failures and zero ignored.
See [retained-compatibility-summary.json](retained-compatibility-summary.json).
The focused positive and retained selections therefore contain 32 successful
native test executions; this is not a full-workspace test claim.

## Source and artifact qualification

The native builds used a partial checkout of the repository. They do not claim a
complete physical tracked-worktree scan. The later negative runs, positive runs
and source gates capture before/after SHA-256 for 297 selected actual source and
manifest files across the four owners, protocol and crypto primitives, plus the
workspace lock and toolchain file. Those selected bytes and their recorded HEAD
remain unchanged during each run. The initial DA negative receipt records its
HEAD, command, raw stream hashes and ELF hash, but does not contain the later
runner's before/after selected-source snapshot.

Native ELF hashes are recorded; executables are not included in this evidence
directory. Old and fixed builds reused target filenames, so the matching receipt
hash, not the executable pathname alone, identifies the observed binary.

The following source gates run on `9021d15ffe1dfdfb1358a2372b5a472babbf80ac`:

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo metadata --locked --offline --format-version 1` | exit 0; 26 workspace members, 177 resolved packages |
| `python3 scripts/ci/test_ci_source_integrity.py` | 43 passed; exit 0 |
| Four affected packages, `cargo clippy --locked --offline --all-targets -- -D warnings` | Two `clippy-driver` SIGKILL reports; no terminal command receipt; incomplete |

The 43 source-integrity tests validate the checker against negative controls;
they do not transform this checkout into a full-source qualified one. The final
combined source admission and authority/corpus pins belong to integration.

Only this task's inactive incremental compiler cache was removed between native
tests and Clippy to recover disk space. Source, generated test ELFs and raw logs
were retained; build flags and profiles were unchanged. The operation is recorded
in [cache-cleanup.json](cache-cleanup.json).

## Interrupted execution and restored original identity

The cloud execution environment became unavailable during the strict Clippy
attempt. After the environment was remounted, the original clean `9021d15...`
worktree, all three original commits and the original C5-prerequisite bundle
were recovered. Raw negative, positive and retained-test streams were checked
against their recorded byte counts and SHA-256 values. All 297 selected source
files still matched the positive observation, and the four positive test ELFs
still matched their recorded hashes. No native tests were rerun for this recovery
check.

The captured Clippy stderr contains `clippy-driver` SIGKILL reports for the MVCC
and DA test targets. No terminal Cargo exit receipt was recovered. A SIGKILL
report does not establish its cause; this evidence does not assert an OOM event
or successful Clippy completion. See
[clippy-incomplete-observation.json](clippy-incomplete-observation.json).

A proposed serial retry did not start. The proposed gzip backup of the native
ELFs also has no completion receipt and is not credited as successful. The four
original positive ELFs remained present and matched their recorded hashes when
checked after remount; none of their bytes are packaged here.

A fallback input package containing newly written DA tests had been saved outside
the repository while the cloud filesystem was unavailable. It was never applied
or executed and is not part of this source history. This evidence uses the
recovered original commits and original native streams, not the fallback.

The complete combined candidate still requires its own committed-source
qualification and strict Clippy. This evidence-only child does not change or
relabel any native tested commit.

## Evidence layout and reproduction

The `negative-native.*` files are the initial DA run. The
`negative-owners-PACKAGE.*` and `positive-owners-PACKAGE.*` triplets retain raw
stdout, stderr and command/source receipts. The `retained-PACKAGE-N.*` files are
the exact single-test invocations. The `gate-*` files retain formatting, metadata,
source-integrity and strict Clippy commands. Their `.json` files bind raw stream
bytes and hashes; [manifest.json](manifest.json) binds all packaged payloads.
Run `python3 verify.py` in this directory to verify the artifact bindings and
recorded result counts. That check does not execute native tests or grant release
acceptance.

The three `run-*.py` files preserve the actual local runner definitions and
recorded paths. A fresh checkout can run the displayed Cargo command per owner
at each exact source commit, then run the named retained tests from the positive
ELFs or through Cargo `--exact`. Do not reuse an old-source executable pathname
as evidence for a different commit. This evidence does not include a new
dependency-policy audit; the #900 archive is explicitly a remote readback.

## Remaining boundaries and integration pins

The patch does not establish protection against a concurrent actor replacing a
directory entry between inspection and open. It does not modify ordinary WAL
recovery protocols, solve Root freshness or external-effect reconciliation, or
prove exploit reachability from network consensus input. SQL rollback cannot
undo an already emitted external action; no claim about external actions is
made by these store-opening tests.

Integration must refresh the settlement `src/store.rs` and `src/tests.rs` content
pins in `config/pon/pq-authority-effects-v1.json`, followed by that authority
file's blob pin in `config/pon/pq-cross-branch-corpus-v1.json`, against the combined
source checkpoint. This branch intentionally leaves that shared integration step
to its owner. The portable settlement classification remains classical bilateral
signatures, and coverage completeness, whole-chain PQ qualification and
production activation remain false.
