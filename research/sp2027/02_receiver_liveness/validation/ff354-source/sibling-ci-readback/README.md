# Failed QROM sibling CI readback at ff35430d

`../SIBLING_CI_READBACK.json` records the actual first concrete failure in four
jobs across runs 43131136371 (closure) and 43131136548 (implementation). Both
head and prospective-merge jobs failed; no claim of globally green CI is made.
`current/` retains complete returned decoded logs plus saved run/job API JSON.
`prior-0bc/` retains the exact four older decoded logs used for comparison; every
old log hash matches the previously saved audit at batch ci-43125548321.

The closure first failure remains the consensus source SHA mismatch in the
unchanged lifetime `SOURCE_PINS`. The implementation first failure remains
11172 actual bytes exceeding a 9233-byte bound for the W1 verifier's `main.rs`.
The implementation logs also retain the test assertion that expected a
different pinned-drift message. That secondary exception already occurs in
the older original logs. The observed exception-message sets are unchanged.

All nine selected target, contract, helper, test and workflow files are
byte-identical in Git at common base `5b591754b426c6f88bea6d399fafcd77e31255d8`,
earlier head `0bc51795a978494af1b4659712ecf78c290c1a88`, and execution head
`ff35430d27eea56dd803e05aa6d48573e37ed4c9`. This establishes that these observed
failure predicates predate SP27 changes; it does not certify unexecuted later
stages or attribute every other CI failure. No base CI, test, native executable,
or gate was rerun or modified for this audit.

From the Chain root, the saved audit source can be run without any Git lazy
fetch or overwrite of the saved result:

```bash
READBACK=research/sp2027/02_receiver_liveness/validation/ff354-source/sibling-ci-readback
python3 "$READBACK/audit_sibling_ci_ff354.py" --repo . \
  --current "$READBACK/current" --prior-logs "$READBACK/prior-0bc" \
  --prior-audit research/sp2027/02_receiver_liveness/batches/ci-43125548321/SIBLING_QROM_CI_AUDIT.json \
  --out /absolute/new/SIBLING_CI_READBACK.json
```

`FILES.json` binds the exact logs, metadata and audit source, and records that
the existing parent `MANIFEST.json` and `validation-records.zip` remained byte
identical. They were not edited or repackaged. This README is a later description
outside that file manifest's recorded set.
