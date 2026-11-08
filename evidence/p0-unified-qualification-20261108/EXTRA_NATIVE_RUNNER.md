# Extra native observations on the frozen unified source

`run-extra-native.py` is an additional execution receipt collector. Its result is
always scoped to `COMPONENT_OBSERVATION_ONLY`; production activation, original
resource confirmation, whole-chain quantum security, and throughput improvement
remain false. Preparing the command list or passing the runner's control tests
does not execute native code or establish those qualifications.

## Source and environment

Run it only after committing the complete unified candidate. Supply the exact
commit using `--expected-head`. The source, Cargo target, and new output directory
must be canonical absolute paths in separate trees. An existing output directory
is refused. There is no retry or historical DAA fallback.

The runner reuses the environment, provider identity, source identity, readback,
and SQLite build-marker helpers from
`../pq-authority-preflight-20261108-9d315/authority-final-validation-runner.py`.
That original 32-command file is unchanged and must have SHA-256
`d81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710` before it is
loaded. Its exact checked bytes are compiled into the helper module. Rust 1.95.0,
the reviewed OpenSSL 3.5.9 provider, offline locked dependencies, two build jobs,
and one test thread are inherited without adding native profile overrides.

When sharing `--target`, finish the original 32-command runner before starting
the extra runner. The extra runner does not start the original runner and does
not claim that the two runs contain disjoint tests.

```bash
python3 -B "$qualification_repo/evidence/p0-unified-qualification-20261108/run-extra-native.py" \
  --repo "$qualification_repo" \
  --expected-head "$qualification_head" \
  --target "$qualification_target" \
  --out "$qualification_out"
```

Add `--list-commands` to inspect the 17 commands without creating output or
starting child processes. This mode is a plan, not an execution receipt.

## What executes

The sequence performs preflight and the raw-source guard, observes tool versions
and the current complete Cargo workspace metadata, then issues exactly one:

```text
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml
  --workspace --all-targets --all-features --no-fail-fast
  --message-format=json-render-diagnostics
  -- --show-output --test-threads=1
```

The runtime uses the fixed absolute Cargo path from the original helper. It does
not run the previously selected Node targets a second time. Instead it requires
actual nonzero execution for all ten targets: `native_full_relation_context`,
`work_header_binding`, `growth_persistence_cancellation`, `work_fuzz_semantics`,
`daa_joint_consensus`, `daa_adversarial_schedule`, `native_owner_journal`,
`native_owner_observation`, `native_risk_ledger`, and `native_node`.

The same observation must contain the crypto library's `pon_work::` group and
the Node library's `consensus::tests::`, `store::legacy_reorg_root_tests::`, and
`store::reorg_readback_tests::` groups. Cargo compiler artifact identities are
matched to the Cargo-dispatched test paths and their post-run SHA-256 file hashes.
This is `CARGO_DISPATCH_AND_POST_RUN_FILE_HASH`; OS loaded image identity is
explicitly `NOT_OBSERVED`. Every workspace member must have an observed harness,
and compiled test executables
must match the dispatched inventory. Ambiguous or incomplete attribution cannot
pass the readback.

Each harness retains its passed, failed, ignored, measured, and filtered counts,
test names, expected-panic annotation, and the bounded binary identity observation. A zero-test
example or binary is `NO_TESTS`, never a passing test harness. A fully ignored
harness is `IGNORED`. A required target or unit group with zero actual execution
blocks the required roster even if other targets passed. The unfiltered
workspace command refuses unexplained filtered counts. Workspace coverage is a
harness inventory claim. Each member separately records actual executed, failed,
ignored and zero-harness counts; merely having a harness does not mean that
member executed nonzero tests. Unattributed output after the last harness summary
cannot be discarded from the accounting.

The fresh identity and qualification gate suites also execute without filters.
Their raw counts, errors, failures, and skips remain visible. Zero-test and
all-skipped Python suites cannot pass. Exactly one successful terminal is required;
an `OK` line cannot hide a failure terminal or nonzero failure/error counters.

## Fresh DAA evidence and independent readers

Only the workspace test process receives `TRNM_DAA_EVIDENCE_DIR` and
`TRNM_JOINT_DAA_EVIDENCE_DIR`. Both output roots must be absent immediately before
that process is dispatched. The source fixtures use create-only exports. A
complete new 84-packet DAA directory and separate 114-packet PNH1/PGH2 directories
are inventoried and hashed after that process.

The two reader implementations consume only these new directories, with report
digests obtained from this execution's manifests. The existing DAA controls, the
new head-binding controls, and both profile control suites receive explicit
`--raw-dir` arguments for the fresh output. Their default historical fixture
directories are not used by this runner. Reader report identity, full-proof
count, packet inventory and limited-authority flags must match the fresh native
export. PNH1's PGH2-only skip remains visible.

A complete export may be independently read after a failing native command, but
the producer's actual failure remains in the receipt and prevents overall
component success. Missing or partial exports block their readers. Raw exports
are hashed again after readback; changing them cannot pass.

## Retention and interpretation

Every dispatched command retains its exact argv, source head, environment
additions, timestamps, actual exit code, stdout and stderr bytes and hashes.
Failed native output is parsed as well as successful output. Infrastructure
errors and the inherited 7,200-second process watchdog remain `UNKNOWN` where
appropriate. This watchdog does not replace any fixture's four-second business
deadline. No deadline, resource budget, feature, assertion, or ignored test is
silently changed.

The raw-source guard runs before and after the batch. HEAD, tree, index, tracked
locks, clean status, fixed provider inputs, the immutable original helper, and
SQLite build qualification markers are checked again at the end. All attempts
and failures remain in `summary.json`; source checks cannot grant model or
release qualification.

`components_passed` can be true only for the recorded executed scope. It does
not turn `NO_TESTS` or ignored helpers into tests, combine other branches' results,
or promote the constant qualification flags. The original 32-command run and
this run must keep separate receipts even where their test coverage overlaps.

## Optional full-path cost observation

`--fullpath-plan` prints the accurate extra release build, native collector, and
adapter argv without executing them. That observation requires a separate
release build of `native_fullpath_v1`, so it is intentionally outside the core
17-command sequence. Its output directory must be fresh. The adapter argument
must use the SHA-256 of that run's `preregistration.json`; its normal exit is 1
because it always retains the qualification hold.

The original collector's four offered starts, full proof, duplicate, late-product
case, cancellation, 60-second process watchdog, and four-second/depth-six
business checks remain unchanged. Existing measures include parent-plus-child
CPU time, an RSS upper bound, same-host IPC input bytes, and native process/event
timing. WAN costs, disk IO cost attribution, lock cost, queue cost attribution,
and a comparative throughput improvement remain `UNKNOWN`. This is one new
component observation, not a claim that the original 0.25-core resource contract
was enforced or that P2 improved.

## Runner control tests

```bash
python3 -B evidence/p0-unified-qualification-20261108/test_run_extra_native.py
```

These controls exercise omissions, zero-test runs, ignored helpers, native
failures, namespace aliases, artifact identity gaps, filtered counts, ambiguous
summaries, fresh-output refusal, immutable-helper checks and reader binding.
They use synthetic parser inputs and temporary paths. They are not native
execution evidence and cannot satisfy the required native roster.
