# Native upgrade implementation observations — 2026-10-18

These are actual native Linux component executions on the configured `main` host.
The raw outputs retain their original source commit and tree. They are not a
substitute for a later integrated-source run, an independent operator campaign,
or an installed model's future utility.

## Executed source scopes

| Source | Actual execution | Result |
| --- | --- | --- |
| `d76a0d0d1f8d8d685d40816ad1978b52f3aa97d0` | Complete worker target, including the ordinary CLI timeout, bounded log and private stdio tests | 369 passed |
| Same source | Exact accepted-task observation through native execution, CLI restart, heavier fork and corrupted state | 4 passed |
| Same source | Existing native node integration target | 30 passed; 1 explicitly ignored test retained |
| Same source | Workspace formatting and strict Clippy for worker/node, all targets | Passed |
| `336f95bd93df803527afdb50a9a4e1c8992bcbc8` | Complete MVCC target, including integrations and documentation | 123 passed; 6 explicitly ignored tests retained |
| Same source | Existing live-state validation and accepted-task observation | 3 + 4 passed |
| Same source | Strict Clippy for MVCC/node, all targets | Passed |
| Same source | Explicit release encoder comparison | Passed; all paired timing samples retained |

See [component-observations.json](component-observations.json) for the exact trees,
durable runtime job identities, counts and reconstructed medians. The two
`results.json` files retain the actual commands, exit codes and elapsed times;
adjacent `.log` files are the corresponding original native output. The
[transport manifest](transport-manifest.json) binds each transferred file's bytes
and SHA-256. These are separate executions, not additive unique-test counts.

## Measured encoding component

The same release binary alternates the previous allocating reference and the
buffer-reusing implementation. Each arm has 16 samples with 16 full comparisons
per sample. The supplied values, keys and equality result are identical.

| State keys | Previous median per comparison | Reused-buffer median | Median elapsed reduction |
| --- | --- | --- | --- |
| 64 | 47.637 µs | 41.797 µs | 12.26% |
| 512 | 379.917 µs | 342.874 µs | 9.75% |
| 4,096 | 3.208 ms | 2.751 ms | 14.23% |

This measures canonical-byte comparison. It excludes SQLite, execution, state-root
construction, history traversal, networking, recovery and durable confirmation.
The implementation still validates the full retained state and history where the
original owner requires them. It makes no sublinear-state, physical-memory,
public-TPS or p95/p99 improvement claim.

## Metric boundaries

The six end-to-end metrics in the sole development plan are explicitly null in
this component report. A functional reorg test does not measure recovery capacity;
a canonical encoder benchmark does not count confirmed transactions; accepted
Chain task bytes do not count installed or subsequently qualified Hepta updates.
Actual end-to-end campaigns must retain their own cohorts, wall clocks, source
pair, unresolved outcomes and original owner observations.
