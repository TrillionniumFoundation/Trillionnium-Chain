# PNRL1 confirmation-result type binding regression

This record concerns the local Python reader that binds a retained PNRL1 risk
bank to an independently checked PNOJ1 native journal. It does not record a new
native execution, a network attack, a probability theorem, or production
qualification.

## Retained artifacts

[typed-binding-reproduction.tar.gz](typed-binding-reproduction.tar.gz) contains
the complete `daa-risk-typed-probe` directory: the old reader source, all nine
mutated bank cases, before/after observations, failed and successful test logs,
and the complete historical fixture copy. The restored empty directory
`fixture-copy/foreign-native/packets` is included. No case was dropped.

The archive contains 59 regular files and 32 directories, including its root.
Paths are sorted; tar timestamps, uid/gid and owner names are normalized; the
gzip timestamp is zero and its filename is empty. File contents are retained.

The four uncompressed records outside this directory are
[summary.json](../summary.json), [before.json](../before.json),
[after.json](../after.json), and
[fixture-restoration.json](../fixture-restoration.json).
The final frozen-source command records and original stdout/stderr are in
[python/joint-risk](../python/joint-risk/validation.json).
[SHA256SUMS](../SHA256SUMS) lists every staged file except the checksum file
itself.

## Observed defect and correction

Python container equality treats `False == 0`, `True == 1`, and `1 == 1.0` as
equal. The old reader used that equality to compare the complete native
terminal result with the risk bank's `confirmation_wrapper_result`.

Eight retained mutations changed nested boolean or integer values to different
JSON types while retaining Python equality. With the original native journal
unchanged and without the original bank checkpoint, all eight were accepted by
the old reader. An additional-field control was already refused.

The correction compares both complete results using the existing
`native_execution_certificate.canonical` function. The same eight mutations
and the additional-field control now all refuse with
`R_NATIVE_OUTCOME_BINDING`.

The original bank checkpoint refused all nine rehashed bank copies with
`R_CHECKPOINT_MISMATCH` both before and after the correction. This independent
pin protection was never bypassed or relaxed.

The returned `native_confirmation_result` comes from the independently checked
native terminal. The reproduced defect is an exact type-binding failure in the
local evidence reader; it is not an observation that native confirmation
changed from false to true.

The comparison preserves the types of parsed JSON values. The negative-zero
controls use floating-point `-0.0`. This change does not introduce a new raw
JSON lexical encoding rule: an integer token `-0` parses as integer zero, and
JSON object key ordering is not asserted to be an authority boundary.

No PNRL1/PNOJ1 schema, hash domain, risk-accounting rule, checkpoint rule, or
qualification flag was changed by this correction.

## Preserved test outcomes

The new two-test regression run against the retained old reader failed in
11 type-alias subcases. Its original failure log remains
`before-tests.log` inside the archive.

The first full run after the correction executed 27 tests and retained one
error: the archived foreign native journal lacked its empty `packets`
directory, so the pre-existing cross-owner test raised `FileNotFoundError`.
That failure remains in `after-tests.log`.

A scratch copy restored only `foreign-native/packets`. All 31 existing fixture
files retained their exact bytes, as recorded in
[fixture-restoration.json](../fixture-restoration.json). The full test module
then passed 27/27. The original success log remains
`after-restored-fixture-tests.log` inside the archive. The historical repository
fixture was not edited.

The fixture originated at
`evidence/pon-joint-state-risk-ledger-20261107/final-source-gates/merged-native/original/attempt-02/fresh-native-risk/`.
Re-reading this fixture with a new Python reader is not a new native execution.

## Final frozen-source verification

The final verification used commit
`d23488c5f9b4a6696c3799b12f14b8af0a1b81fc`, tree
`72b106b4458299c37da146b0218b8f5276195b6d`.

| Command group | Observed result | Exit |
| --- | --- | ---: |
| Project preflight | PASS | 0 |
| Native risk reader tests | 27/27 PASS | 0 |
| Joint qualification tests | 34/34 PASS | 0 |
| Joint qualification `--check` | Contract consistency PASS; qualification HOLD | 0 |
| Joint qualification `--require-qualified` | `REFUSED_UNPROVED_JOINT_CONSENSUS` | 3 |

The final records retain command argv, cwd, actual execution-relevant
non-sensitive environment variables, separate original stdout/stderr, exit
codes and file hashes. Source identity, tracked-tree cleanliness, selected
source bytes and all 31 fixture files were unchanged across that verification.

Joint qualification remains `HOLD_NO_GO`.
`security_probability_calibrated` and `production_activation` remain false;
`actual_lifetime_failure_bound` remains null. The expected refusal exit is not
a successful security qualification.
