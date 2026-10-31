# Fresh kernel-quota checks inside native History

## Result and remaining gate

This lane reduces allocation and immutable path-construction work inside the
existing resource check. It does **not** reduce checkpoint frequency, skip any
current file read, retain a resource verdict, or change native State/History
validation. The original honest-service deadline remains open.

A retained native test binary executed the old and new five-file read paths on
the same real Linux root cgroup. Across five alternating rounds, each with
1,000 iterations per arm, median thread CPU time was **10.563727 ms before** and
**9.954222 ms after**, a **5.7698% reduction in this measured scope**. Median
wall time was 10.646319 ms and 9.956680 ms. The candidate was slower in the first
round. These are small, shared-host observations, not a stable performance
guarantee or a native History service result. See the [lossless raw native output](quota-read-cost-first-binary.stdout.log.gz),
[process receipt](quota-read-cost-first-binary.process.json), and
[derived summary](measurement-summary.json).

The measured root cgroup was **not** an eligible fixed parent: before and after
the run, `cpu.max` was `800000 100000`, `memory.max` was 8 GiB, and swap/pids
limits were `max`. The measured source asserts that both paths return the same
result but does not print that result. The raw surrounding file observations
are retained in the process receipt. This observation must not be described as
a successful fixed-parent check, a cold-host measurement, or the original
30-second service gate passing.

## Source binding

The local parent is `7da4964d02b42076996e89a78d13f68572d33be5`.
Only [host_kernel_parent.rs](../../../trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs)
changes production behavior in this lane.

| Item | SHA-256 |
| --- | --- |
| Host source compiled by the successful first native build | `481efb469168c69a9c88b90355a7f8acbab32e14ba2b22d3a028e1c4bf42d14c` |
| Intermediate measurement-reporting source used by the three failed rebuilds | `73262238a015a80fcaa51f51c0a598bb79b86aa04fffe2c407ea6bf5e3ad5469` |
| Final host source, including the required test-only Clippy correction | `e81f3620590bfd75e4eb5fb123d20929d326c438882923f31012a2fb30f36155` |
| Retained native binary used for the measurement | `51ddbf0b961f7e8f41c2b69c15b93e25440f941735ac7a03cf5406f6dee46467` |

The [compiled source snapshot](compiled-host_kernel_parent.rs.txt) was recovered
by reversing only the later measurement-reporting edit and exactly matches the
source hash captured before and after the successful build. The
[complete subsequent diff](benchmark-reporting-only.diff) is confined to the
ignored measurement test: it adds an explicit verdict to the output and refuses
to measure an early I/O failure, producing the
[intermediate source](pre-clippy-host_kernel_parent.rs.txt). Strict Clippy then
required replacing an indexed test loop with direct iteration over the same
five paths. The [recorded test-only correction](clippy-test-loop-fix.json)
preserves the path order and every assertion. The
[final source snapshot](final-host_kernel_parent.rs.txt) retains the stronger
measurement precondition. Production code is byte-identical across all three
sources; [source binding](source-binding.json) verifies that the later changes
are confined to these two test functions. **Exact final native execution remains
pending in hosted CI after three compiler SIGKILLs on the intermediate source.**
The earlier binary is not relabeled as a build of either later source.

## Production change and invariants

`KernelBudget::open` prepares the five immutable paths under its already
canonical, approved fixed parent. Each later check still opens every current
path using the caller's current credentials. No file descriptor, permission,
metadata, membership, quota content or successful verdict survives a check.

The existing 128-byte quota recheck uses a private 129-byte stack buffer. It
still retries `Interrupted`, rejects every other I/O failure, waits for actual
EOF even at exactly 128 bytes, and rejects a 129th byte. UTF-8 validation occurs
before text is exposed. Initial quota parsing, boot identity, and actual calling
thread membership retain their original unbounded text behavior.

All five quota reads still occur left to right before parsing any quota. A bad
first value therefore cannot hide an unavailable later file. The public error
mapping, numeric bounds, immutable-limit comparison and parent identity checks
are unchanged. CPU token parsing no longer allocates a vector; checking that the
actual thread belongs to the parent subtree no longer allocates a formatted
prefix. The same path and grammar rules remain in force.

This patch does not touch SQL reads, account graph validation, PQ validation,
work validation, ancestry, fault/debt/accounting, reorganization, durable state,
quotas, deadlines or checkpoint scheduling. It adds no graph-validity cache.
The possible 8,192-entry arithmetic-cache eviction optimization was not applied:
this lane has no evidence that the original failing service workload reaches
that capacity boundary.

## Actual controls and failures

| Check | Actual result | Scope |
| --- | --- | --- |
| Native kernel-parent controls | 19 passed, 0 failed, 1 manual measurement ignored; 854 filtered | First compiled source; identical production code, with the later test-loop correction separately disclosed |
| Retained-binary old/new real-file measurement | 1 passed, 873 filtered | Five root-cgroup quota reads and parsing only |
| Final workspace formatting | Passed | `cargo fmt --all --check`; final host source hash recorded |
| Source-integrity negative controls | 34 passed | Independent temporary Git/filesystem fixtures, not a full identity check of this sparse worktree |
| Full offline Cargo metadata, two attempts | Exit 101 in each | Initially missing cached `anstream v1.0.0`, then `bumpalo v3.20.3`; no successful full-graph claim |
| Final measurement-only native rebuild, first attempt | Exit 101 after rustc received SIGKILL | No final native execution took place |
| Final measurement-only native rebuild, second attempt | Exit 101 after rustc received SIGKILL | No final native execution took place; OOM kill counter increased during this run |
| Final measurement-only native rebuild, exclusive lane retry | Exit 101 after rustc received SIGKILL | Frozen checkpoint `ba217288`; OOM kill counter increased from two to three |
| Strict Clippy on intermediate source | Exit 101 with `needless_range_loop` | A real test-code lint; corrected without suppressing the lint or dropping a control |
| Strict Clippy on final source | Exit 101 after clippy-driver received SIGKILL | Exact final source and unchanged strict flags; final strict-check gate remains open |

The new default controls compare the actual production helper with the retained
pre-change reader/parser. They exercise short reads, interruption, late I/O
failure, invalid UTF-8, the exact limit and oversize frontier, malformed grammar,
file replacement/removal, permission changes under actual credentials, and
the read-before-parse error precedence. Initial calls use newly created files;
subsequent mutations must be observed afresh. They do not claim OS-cache eviction
or a cold fixed-parent service run.

The successful first build is recorded by
[native-controls.process.json](native-controls.process.json), with its raw
[stdout](native-controls.stdout.log.gz) and [stderr](native-controls.stderr.log).
The later failed build is separately retained in
[quota-read-cost.process.json](quota-read-cost.process.json) and
[its stderr](quota-read-cost.stderr.log). The failure reports SIGKILL, **not**
ENOSPC. A later [resource snapshot](shared-resource-after-failure.json) observes
memory pressure and an OOM counter, but no before-run counter exists for that
attempt; it does not establish the cause of that signal. The second rebuild's
[process receipt](native-controls-final.process.json) and
[stderr](native-controls-final.stderr.log) independently retain another SIGKILL.
Its [resource window](second-build-resource-window.json) observes `oom_kill`
increase from one to two, with roughly 9 GB of disk available after the failure.
The counter does not identify the killed PID. A third
[frozen-checkpoint process receipt](native-controls-final-retry2.process.json)
records another SIGKILL after 56.434 seconds and captures the OOM kill count
increasing from two to three. All three attempts stopped before executing the
native tests; no final measurement or second native binary was produced. The
[first strict Clippy diagnostic](clippy-final.stderr.log) is independently
retained as an actual lint failure, not confused with those compiler signals.
After that test-only correction, the [final strict retry](clippy-final-retry1.process.json)
also stopped with [SIGKILL](clippy-final-retry1.stderr.log) after 200.689 seconds;
it emitted no new lint diagnostic. The final source passed
[workspace formatting](format-after-clippy-fix.process.json), but no final
native-execution or strict-Clippy success is claimed.
The initial formatting failure and
the offline metadata failure are also retained rather than overwritten by later
successes.

Captured output with trailing whitespace or a final blank line is retained in
lossless gzip, with [explicit original/compressed byte and hash bindings](compressed-logs.json).
Decompression was checked against the original committed bytes. This preserves
the actual output while allowing the final all-files diff check to remain
strict. The earlier [whitespace observation](whitespace-validation.json) remains
as history and is not claimed as an all-files pass.

To release shared capacity after the runs, the native binary was first moved
out of this lane's target directory on the same filesystem and its hash checked.
Only `/tmp/pon-history-target` was then deleted. The retained binary was
compressed, its decompressed hash checked, and the raw copy removed. The
[release receipt](target-release.json) records the exact paths, hashes and
released capacity. No other target directory was changed. That exact original
gzip was subsequently split without recompression into three pieces no larger
than 7,000,000 bytes for publication. The
[archive manifest](native-first/manifest.json) records each piece in order,
every piece's length and hash, the complete gzip length and hash, and the
decompressed binary length and hash. The actual
[standard-library readback](native-first/readback.stdout.json) passed and
explicitly performs no native execution.

## Reproduction and integration

The original complete argument vectors and before/after source hashes are in
the process receipts. The local build used Rust 1.95.0, one build job, no
incremental compilation and no test debug information. The repository's existing
optimized test profile and its debug/overflow checks were retained. The
[compiler version](rustc-version.txt) is included.

Verify and decompress the ordered retained-binary fragments without executing
them using only Python's standard library:

```sh
python3 evidence/pon-security-sprint-20261031/history/verify_native_archive.py \
  evidence/pon-security-sprint-20261031/history/native-first/manifest.json
```

Adding `--output /tmp/pon-history-restored-native` writes the verified executable
to a new path and refuses to overwrite an existing file. The reader verifies
all piece hashes, complete gzip bytes/hash and decompressed native bytes/hash
before publishing that output. [Its source](verify_native_archive.py) and actual
readback records are retained with the fragments.

After `bash scripts/project-preflight.sh`, the final native commands to rerun
with an adequately populated Cargo cache and sufficient resources are:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --profile test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib \
  host_kernel_parent::kernel_parent -- --nocapture

CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --profile test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib \
  actual_kernel_quota_read_cost_preserves_all_fresh_reads -- --ignored --nocapture
```

The integration owns the exact committed-source identity check, complete locked
dependency graph, strict Clippy and required CI. This lane's earlier offline
cache failures remain independent observations and do not override separately
retained integration graph results. This lane's
checkout intentionally excludes historical evidence, so it cannot certify a
full tracked worktree identity. Its negative source-integrity tests remain
valid independent fixture executions.

The decisive next measurement remains the original fixed-parent native service
campaign, with the same honest workload, original deadlines/quotas, current
reads and validation obligations. Include no-attacker, cold-start and sustained
adversarial controls. Profile the whole callback as well as State/History so
that this small five-file observation cannot conceal costs in boot, membership,
metadata, graph validation or kernel scheduling. If that campaign still misses
the deadline, this patch must remain a partial improvement; its result cannot
close the service gate.
