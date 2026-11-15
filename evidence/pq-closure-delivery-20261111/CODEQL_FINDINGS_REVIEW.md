# C1 CodeQL findings: bounded path and input review

**The retained Rust results contain 857 distinct primary source locations across
95 files. This review inventories those locations; it does not resolve, suppress,
or establish exploitability of any finding.** Both source lanes remain separate
observations. Their duplicate locations are counted once in the table below.

The complete machine-readable inventory is
[codeql-findings-review.json](codeql-findings-review.json), 383,182 bytes, SHA256
`26a8f9a6683d1a890ec7cc121f613737107a06fd50ad7ad352625e1b74c9ffef`.
It retains every primary location, message, path classification, C1 source-file
pin, input archive/member hash, and the bounded Python reference searches.

## Exact inputs and counting method

This review reads the six local SARIF artifacts already retained for run
`42955582992` in the [C1 hosted packet](../pq-closure-hosted-c09dbbe992/README.md).
It makes no new GitHub/CodeQL query and runs no test, suspect regular expression,
native workload, or source script. The original SARIF and frozen evidence were
not changed.

The source identities are C1 head
`c09dbbe9921da12db8bf7240a8a95a0e9a789e50` and prospective merge
`61589dddd13e7495369aaecad9212668049417c1`, both tree
`f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6`. Every SARIF lane's before/after source
records agree. The input [bounded archive](../pq-closure-hosted-c09dbbe992/bounded/bounded-readback-c09dbbe992.tar.xz)
has SHA256 `9f7f152885e9eb54725a5fe8909ce90ee5ac23a62facff20f39d0702d2fd22a8`.
Its manifest covers the six ZIPs, and the JSON records their exact SARIF members.

Each Rust lane has 857 raw results for `rust/hard-coded-cryptographic-value`,
giving 1,714 records across both lanes. Their result-array ordering and local
artifact indexes differ. The complete result multisets match after ignoring
only artifact-location indexes; those indexes were separately checked against
each lane's URI table. The primary URI/region/message multisets match exactly.
Thus there are **857 primary URI/region keys and 95 URIs** across the two lanes,
not 1,714 distinct reviewed issues. Every result has one primary location.
Related locations are retained in the original SARIF and are not counted as
additional findings here.

A location key is the exact relative URI plus the supplied primary region
fields, excluding a possible snippet. These keys are not assertions that there
are 857 independent security defects. All 95 Rust URIs occur in the frozen C1
tracked source snapshot. The Python source reads were compared with that same
snapshot's size and SHA256 pins, retained in the
[original C1 native archive](../pq-closure-native-observations-20261111/original/native-original-c09dbbe992.tar.xz).
This is source binding, not host or execution attestation, and supplies no C2
scan result.

## Rust: mechanical path categories

Categories are assigned in this order: an `evidence` path component; explicit
fixture/data components; a `tests` component or test-style Rust filename;
benchmark paths; examples; formal paths; remaining `src` paths; other paths.
The test filename patterns are `tests.rs`, `test_*.rs`, `tests_*.rs`, `*_test.rs`,
and `*_tests.rs`. The explicit fixture components are `fixtures`, `testdata`,
`test-data`, `test_vectors`, and `test-vectors`.

| Mechanical category | Files | Distinct primary locations |
| --- | ---: | ---: |
| Test directory or test-style filename | 69 | 721 |
| Remaining `src` path | 11 | 101 |
| Example path | 8 | 27 |
| Formal path | 6 | 6 |
| Evidence path | 1 | 2 |
| Explicit fixture/data path | 0 | 0 |
| Benchmark or other path | 0 | 0 |
| **Total** | **95** | **857** |

These are pathname observations. A test-style filename does not prove exclusion
from a deployed build. Conversely, a remaining `src` file may contain test-only
modules. This review did not inspect Rust `cfg`/feature gates, callers, deployed
entry paths, values' intended roles, nonce uniqueness, key lifecycle, or the
interprocedural paths represented by the query. A zero in the explicit fixture
bucket does not mean the repository contains no fixtures or that no flagged
literal is fixture data.

For a bounded next source review, the remaining `src` bucket contains the
following 11 files. All paths below have prefix `trillionnium/crates/`; the JSON
contains exact regions and source pins. This list is a work queue, not a risk
ranking or a classification as production vulnerabilities.

| Source path after the prefix | Locations |
| --- | ---: |
| `trnm-types/src/relay.rs` | 43 |
| `trnm-types/src/transcript/mod.rs` | 19 |
| `trnm-transport/src/lib.rs` | 12 |
| `trnm-pon-node/src/store/task_observation.rs` | 6 |
| `trnm-protocol/src/funded_service_task_v1.rs` | 6 |
| `trnm-pon-node/src/ancestry_index.rs` | 4 |
| `trnm-worker-agent/src/workflow_ops.rs` | 4 |
| `trnm-pon-node/src/ingress.rs` | 3 |
| `trnm-crypto-primitives/src/pq_auth.rs` | 2 |
| `trnm-crypto-primitives/src/pq_candidate.rs` | 1 |
| `trnm-mvcc-fee/src/public_evaluation.rs` | 1 |

The other 756 locations remain in the review inventory. Their path labels are
not dismissals. No finding was assigned false-positive, unreachable, fixed, or
resolved status.

## Python: two locations and their actual inputs

Each Python lane contains two `py/redos` results, and the result arrays match.
Both files live under
`evidence/pon-throughput-continuation-20261104/parent-and-tail/ci/`:

| File | Retained region | Repository selection |
| --- | --- | --- |
| `workflow_wiring_static.original.py` | Line 60, columns 44–50 | Fixed historical absolute scratch checkout |
| `workflow_wiring_static.py` | Line 79, columns 44–50 | `--repository`, defaulting to the repository containing the archived helper |

Both flagged expressions are inside `test_names(path, prefix)`. The function
reads `(ROOT / path).read_text()` and applies the same `re.findall` pattern:

```python
r'#\[test\]\s*(?:#\[[^\n]*\]\s*)*fn ([A-Za-z0-9_]+)\('
```

The six call sites in each script pass literal Rust source paths. The regex
input is their file content, not their pathname. No length bound appears in
the inspected `read_text`/`test_names` function. The six relative paths, all
under `trillionnium/crates/`, are:

- `trnm-mvcc-fee/src/pon_executor/canonical_comparison_tests.rs`
- `trnm-mvcc-fee/src/pon_commitment/unchanged_snapshot_tests.rs`
- `trnm-pon-node/src/store/append_readback_tests.rs`
- `trnm-pon-node/src/store/native_authenticated/post_write_readback/pre_write_tests.rs`
- `trnm-sqlite-io-boundary/src/transaction_scope_tests.rs`
- `trnm-sqlite-io-boundary/src/known_write_scope_tests.rs`

The parameterized helper lets its caller select a repository. This source
inspection does not establish an attacker's permission to select or alter that
repository, successful passage through all earlier workflow guards, an observed
denial of service, or deployed reachability. No adversarial regex input or timing
experiment was executed.

### Workflow inputs and known replay references

The helper's `FILES` list names these three workflows as **inputs it checks**:

- `.github/workflows/pon-original-workspace-large-state-cpu.yml`
- `.github/workflows/pon-recent-batch-acceptance.yml`
- `.github/workflows/pon-pq-system-continuation.yml`

That list is not evidence that those workflows invoke the helper. An exact C1
literal search for `workflow_wiring_static` across `.github/workflows` and
`scripts` returned no matches (Git exit 1). This search cannot exclude dynamic
imports, generated commands, alternate names, manual calls, or entry points
outside those two directories.

The same frozen historical evidence directory contains a documented manual
`python3 .../workflow_wiring_static.py --expected-pre-write-count 13 --output-dir ...`
replay command and two retained replay receipts. Both receipts record exit zero
for historical static-only observations. The pinned replay receipt's script
SHA256 matches the flagged C1 derivative; the earlier receipt identifies a
different script revision. These are known historical references, not newly
executed validations or current hosted workflow invocations. Their exact source
pins, commands, scopes, and script hashes are retained in the JSON.

## What remains open

The path inventory narrows the volume and makes the literal inputs reviewable.
It performs no interprocedural, configuration, deployment, or exploitability
proof. All Rust and Python results remain unresolved by this review.

This supplemental review does not change the original six local analysis
outcomes or the separate **39-poll Code Scanning API export gap**. It establishes
neither zero vulnerabilities nor whole-chain post-quantum qualification.
