# Frozen native source validation and all command outcomes

The recorded native checkout was clean at
`a9efd4cba7546a8ef1e854ee0acdce9f5903ac2d`, tree
`807e589d4cb8c2c0d2c2123e8e4ff0870d6a1eb7`. Every frozen-candidate command
recorded by the command recorder checks all tracked bytes before and after
execution. The baseline build has its separately scoped build receipt. The exact raw local commit is
retained in [tested-local-commit.txt](tested-local-commit.txt); its Git object
hash is the SHA above. Remote commit `b59610295776ea44694ecef97d9f0e1de40bba0c`
has the identical tree and different commit metadata. Later publication changes
preserve the native source, production manifests/lock and test/runner bytes;
their hosted head/merge qualification remains independent. The
[native-source projection](publication-native-projection.json) independently
checks the complete `trillionnium`, `config` and `scripts` subtrees, actual file
bytes/modes, the 12-package scan-lock closure and unchanged historical files.

## Results

| Check | Actual outcome |
| --- | --- |
| M06 full lib, all features | 141 passed, zero failed, nine ignored; 30.48 s |
| Node full lib, all features | **1,150 passed, three failed, 31 ignored**; 1,305.61 s |
| Cell/data availability full lib, all features | 353 passed, zero failed; 33.18 s |
| SQLite boundary full lib, all features | 13 passed, zero failed |
| Workspace Clippy, all targets/all features, warnings denied | Passed |
| Full offline locked Cargo metadata, all features | Passed |
| Workspace formatting | Passed |
| Failed-confirmation reader controls | 149 passed |
| Fresh-service reader controls | 20 passed |
| PQ source-integrity controls | 37 passed |
| PQ exact-source check | 562 blobs checked; product remains HOLD_NO_GO |
| Source-integrity negative controls | 43 passed |
| Command recorder controls | Four passed |
| New reorg ABBA runner controls | Three passed |
| Repository/local Markdown links and native inventory | Passed on the frozen source |
| Explicit repeated-sender cost test | One named test executed; 84 retained rows |

The new four inbound regressions and five Legacy reorg regressions all passed
inside the full Node execution. The full Node result is nevertheless failed.
The 31 existing ignored Node tests were not converted to successes or removed
from the roster. This table is not a claim that every workspace integration,
release-only or original Host test ran locally.

The three failed tests share independent-witness startup in
`pq_rollback_witness/combined_tests.rs`. The child failed before its ready
signal at `UnixListener::bind`; independent Python and direct libc probes show
that the environment rejects **AF_UNIX socket creation itself** with `EPERM`,
before bind/listen. The affected source files are identical at e70, a9, 271a
and b596. [The complete diagnosis](node-unix-socket-failure.json) retains all
three names, both panic locations, probe results, source hashes and the missing
business coverage. The Node/Submit path had not begun. No permission policy,
test expectation or ignore list was changed, and this diagnosis does not turn
the three failures into passes.

## Compiler, logs and unsuccessful setup

Rust/Cargo 1.95.0, locked offline dependencies and the pinned OpenSSL 3.5.9
provider were used for the all-feature tests. Builds used one Cargo job and no
incremental compilation. `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0` disable debug information; the repository's
per-package optimization, assertions and overflow-check policy are retained.
These functional test timings are not native release performance claims.

Every original JSON command receipt is byte-preserved. Log files are compressed
with gzip; [retained-files.json](retained-files.json) maps each original filename
to its retained file, byte length and SHA256. Decompressing a log must reproduce
the `log_sha256` in its command receipt. The complete Cargo graph is retained,
as are the real failed Node output and negative-control diagnostics.

The first release build's stale-baseline dependency failure and the successful
cache-cleared rebuild are both retained. Baseline/candidate binary receipts
record actual hashes, source hashes and unchanged release settings; build CPU
and peak RSS remain unknown. The mistaken zero-test cost selector is retained
alongside its refusal by the named-test reader and the corrected execution.
An exit-zero Cargo command that selects no intended tests is not accepted as
test execution. No raw failed observation is replaced with a synthesized pass.
