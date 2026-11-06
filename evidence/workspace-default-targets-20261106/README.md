# Remaining workspace default-target observations

These disjoint commands used source `e40564bc32d311cb95a284c2bf3cc2a50de551d9`,
whose change from the preceding Node test source was evidence only. Immutable
source checks before and after these final tests verified all 10,400 tracked
entries. No production code or test requirements changed during this work.

## Runtime results

- The 23 non-Node library targets produced **1,745 passed, 6 failed and 10
  ignored** tests. The initial command stopped after audit-events and
  checkpoint-store. A continuation excluded only those completed packages and
  Node, then used `--no-fail-fast` for the remaining 21 library targets.
- The two binary-only packages produced **346 passed and 36 failed** tests:
  trnm-bench was 11/0 and trnm-worker-agent was 335/36.
- Eight default-feature binary targets in mixed library/binary packages
  produced **80 passed and 1 failed** tests. Four contain zero tests; their
  successful test commands do not provide runtime assertion coverage.
- The separate [complete Node library run](../node-default-library-20261106/README.md)
  remains **1,114 passed, 4 failed and 31 ignored**. Its failures are not
  discarded or overwritten by the results here.

All four runtime commands represented by this directory returned exit 101.
The results are not a single successful workspace command. Per-target counts,
raw log hashes and profile choices are in `observation.json`. Gzip files retain
complete original output bytes, including every failure.

The test build retained the repository package optimization settings and used
`CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0` and one Cargo build job.
These functional observations do not establish original-profile or fixed-Host
resource acceptance.

## Failure diagnosis

The six non-Node library failures occur at local Unix socket binding in
checkpoint-store (one) and peer-lease (five), with `EPERM`. The Node binary
failure is `PUBLIC_HOST_PROCESS_UNAVAILABLE` while acquiring its Linux abstract
Unix socket Host slot. No alternative transport or weaker Host guard was used.

The 36 worker-agent failures share incomplete descendant reaping at the
original cleanup deadline. A focused native reproduction retained that failure.
A local diagnostic established that stable live tasks remain listed and their
`stat` files are readable with unchanged task starttime, yet their per-task
`children` files repeatedly return `ENOENT`. Subreaper installation and
`waitid` observation of a direct child's exit worked; the direct child was
finally reaped with its expected exit status. A complete descendant ownership
snapshot nevertheless remains unavailable. Missing `children` files cannot
be treated as an empty child list or as successful cleanup.

No timeout relaxation, successful fallback, ignored assertion, system/network
configuration change or further retry around the established restrictions was
used. These are failed observations requiring a suitable authorized execution
context, not proof that the unexecuted behavior works.

## Compile and source checks

- `cargo clippy --locked --offline --workspace --all-targets -- -D warnings`
  passed for the default-feature eligible targets.
- Metadata lists 383 Cargo targets, but the default command excludes two
  `candidate-recovery-socket` gated targets. A separate strict Clippy command
  for trnm-peer-lease with that explicit feature and `--all-targets` passed.
  This is not one all-features workspace run and does not execute those tests.
- Workspace formatting and immutable-source checks passed.

Runtime integration-test targets, examples, doc tests, the feature-gated owner
binary/integration test and the original ignored release/cost campaigns are
not claimed executed by these commands. The [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains all eight HOLD gates. No release, model-efficacy, public-service,
independent-operation or activation claim is promoted by this evidence.
