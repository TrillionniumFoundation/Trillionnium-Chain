# Native repeated-start ledger: actual execution evidence

This directory retains two real runs of `native_risk_ledger_v1` through
HeptaRuntime's `desktop` host, their full PNRL1 banks and PNOJ1 owner journals,
the native packet files and SQLite stores, raw validation logs, and exact
source snapshots. The wrapper contract and remaining assumptions are described
in [NATIVE_RISK_LEDGER_V1.md](../../../formal/pon-nakamoto-v1/NATIVE_RISK_LEDGER_V1.md).

## Latest source: native prefix readiness correction

The latest source validation job is `1a1b86b72a3-12894-f34`. It passed **11 Rust
tests**, the real child helper exercised by the process-cut test, **25 Python
tests**, independent reading of the retained actual run, and strict Clippy.
Its [exact commands and results](attempt-03/remote/stages.json) and
[source hashes](attempt-03/remote/source-sha256.json) are retained separately.

The [before-fix reproduction](attempt-03/before-repro.json) removes the final
bank lease end and appends a coherent pending charge after the actual native
lease end. The previous reader accepted nine starts and expenditure 37 even
though the native owner was closed. The same private negative bank bytes are
now [rejected](attempt-03/after-repro.json) with `R_NATIVE_START_STATE`.
Both readers now require a same-epoch native opening observation or a completed
non-stopping native call before registration. Additional negative cases cover
unfinished intent/preparation, a new opening still in progress, another epoch,
and a coherently recorded stopping terminal.

The new Rust test uses actual closed and incomplete native owners and verifies
that rejection happens before native recovery or bank mutation. The complete
Rust target was rerun, including its real scenario and child exits. The latest
[local Python test log](attempt-03/local-reader-tests.log) records 25 passing
cases. The latest local and remote independent results are byte-identical.

The two separately retained standalone example runs below belong to the
preceding source versions. They were not rerun after this readiness fix and
are not attributed to the new source snapshot. Their raw journals, packets,
source snapshots, original test logs, and tarballs remain unchanged.

## Retained standalone example results

The earlier full example validation job `1a1b85b51ee-12894-ea8` succeeded with durable, complete,
untruncated output. Its [stages](attempt-02/stages.json) record each exact
command, exit code, and elapsed time. Validation included the four-file
`rustfmt --check`, 10 passing Rust tests, a real example build and execution,
the independent reader, 22 passing Python tests, and strict Clippy with
`-D warnings`. The one Rust child helper ignored by the ordinary test harness
was invoked twice by its parent test to exercise real process exits.

The [actual run](attempt-02/native-run/run.json) and
[independent result](attempt-02/checked.json) contain:

| Observation | Result |
| --- | --- |
| Bank records | 23 |
| Owner leases | 5 |
| Registered confirmation starts | 8 |
| Native confirmation intents covered | 7 |
| Recorded wrapper outcomes | 6 |
| Unresolved, still-charged starts | 2 |
| Declared expenditure | 36 units |
| Remaining declared capacity | 4 of 40 units |
| Unit denominator | 1000 |
| Global failure probability | `null` |

The example uses actual native admission, activation, and confirmation. It
retains an unconfirmed result, a successful result, a repeated successful
statement, an actual membership error, a child exiting after registration but
before native dispatch, and a child exiting after native confirmation but before
the bank outcome. Recovery preserves both incomplete charges without replaying
either operation. A further five-unit registration exceeds the remaining
capacity and is rejected before native dispatch.

The independently rebuilt [earlier local result](local-checked.json) is byte-identical
to the remote result. The [earlier local test log](local-reader-tests.log) records all
22 cases passing against the retained actual run.

## Preserved failures and environment qualification

Attempt 01 completed its real Rust tests, example execution, and independent
read. Its Python test harness then failed before executing the test cases:
the fixture's `cls.run` dictionary shadowed `unittest.TestCase.run`. The
[original failure log](attempt-01/reader-tests.log), original source snapshot,
and original archive remain intact. Renaming the fixture to `cls.document`
resolved that harness defect. Attempt 02 ran all 22 tests against both actual
runs, then reran the native gates on the final source bytes.

Attempt 01 also retained the existing SQLite bounded-I/O build fence's
unqualified-loader warning. Attempt 02 supplies absolute `RUSTC` and `RUSTDOC`
and the canonical toolchain library directory in `LD_LIBRARY_PATH`, as required
by the existing repository requalification procedure. No fence was changed.
The exact inputs are in
[environment-qualification-inputs.json](attempt-02/environment-qualification-inputs.json).
The [retained build outputs](sqlite-build-qualification-output.json) include
both the prior warning and the later `trnm_sqlite_layout_witness` and
`sqlite-3.51.3-normal-native-linux-layout-v3` markers. These are build
qualification observations, not a test of a physical-cost bound.

## Integrity and limits

Each archive was downloaded using a pinned HeptaRuntime binary version, with
per-chunk hashes and the full archive SHA-256 checked. Original tarballs are
unchanged. In the extracted source snapshots, Markdown source filenames use
the suffix `.md.source` so repository link checks do not interpret historical
source snapshots as newly located documents. Bytes and original logical-path
SHA manifests are unchanged. The exact retained-path mappings are in
[attempt-01/retained-source-paths.json](attempt-01/retained-source-paths.json)
and [attempt-02/retained-source-paths.json](attempt-02/retained-source-paths.json).
The readiness-fix snapshot has its own
[attempt-03 source mapping](attempt-03/remote/retained-source-paths.json).

The independent reader enumerates the entire supplied native journal and
requires a registered start for every native confirmation intent. It binds
parsed records and the bank SHA to the same raw snapshot and rejects a file
changed during validation. It checks supplied checkpoint equality without
claiming that the supplied checkpoint is an authenticated latest checkpoint.

The tests preserve two explicit limits. First, after a start but before any
native confirmation intent, a bank-only rollback can erase that start while
leaving the native journal unchanged. Without a newer external bank pin, the
reader cannot detect that history loss; with the retained newer pin it rejects.
Second, coherently rewritten and rehashed historical allowances cannot be
authenticated by an unpinned self-consistent hash chain alone. A previously
retained checkpoint rejects that rewrite. The real child-exit prefixes are
used for the first counterexample.

Declared allowance units remain bookkeeping. The retained result explicitly
sets actual probability-law authentication, conditional allowance proof,
physical preregistration attestation, trusted history anchoring, latest
checkpoint authentication, and world-wide confirmation coverage to false.
The result does not provide physical-clock authenticity, complete hidden
inventory coverage, or a common-law global failure bound.

## Replaying the retained bytes

From the repository root:

```bash
python3 formal/pon-nakamoto-v1/native_risk_ledger.py \
  --run evidence/pon-joint-state-risk-ledger-20261107/native-risk/attempt-02/native-run/run.json \
  --output /tmp/native-risk-rechecked.json
NATIVE_RISK_LEDGER_RUN="$PWD/evidence/pon-joint-state-risk-ledger-20261107/native-risk/attempt-02/native-run/run.json" \
  python3 -m unittest discover -s formal/pon-nakamoto-v1 \
  -p test_native_risk_ledger.py -v
```

[runtime-jobs.json](runtime-jobs.json) binds the runtime job identifiers,
terminal statuses, archive hashes, and preserved failures.
[execution-summary.json](execution-summary.json) records final source equality
and the measured bookkeeping results.
[artifact-sha256.json](artifact-sha256.json) lists every retained file except
itself with its SHA-256 and byte length.
