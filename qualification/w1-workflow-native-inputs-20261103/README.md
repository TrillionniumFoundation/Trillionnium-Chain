# Restore exact W1 workflow inputs

This successor starts at #699 commit `8543bd9f9777d3ef97dbbe55459fa6cb11ec5c2f`.
It changes two workflow inputs. No Rust source, native selector, assertion,
compiler/profile, timeout, workload, resource limit or Host validator changes.
The original #699 jobs remain independent and are not cancelled by this branch.

## Original native controls were rejected after passing

Run `41715157654`, job `126193117518`, executes all six original native control
commands successfully. The History module reports **25 passed, 0 failed,
1 ignored**; the workflow still expects `(22, 1)` and rejects the completed run.
The single ignored test is the original SIGKILL child fixture; its parent still
executes the real kill-cut test.

The three added tests are in `history_import_deadline_tests.rs`, included by
`history_import_tests.rs` as `deadline_controls`:

- `late_admission_keeps_committed_identity_paid_cpu_and_exact_retry`
- `metered_expiry_preserves_native_errors_and_settles_the_original_account`
- `scope_expiry_preserves_cleanup_native_error_and_cold_reopen`

Their exact source blobs and all 26 actual native test names are bound in
`OBSERVED_NATIVE_CONTROLS.json`. `history-import-native-section.txt` retains the
selected native transcript from the decoded original job log with only GitHub's
timestamps removed. Its complete decoded job-log hash is retained; this is a
projection, not a claim that it is the original tee artifact's byte encoding.

The expected count becomes exactly `(25, 1)`. The five other counts and the
existing exact, single-summary match are unchanged. Missing tests, extra tests,
changed ignore counts, duplicate summaries and failed tests still reject.

## Fresh-service preparation omitted the required source receipt

The same run's fresh-service head job `126193117107` stops before native execution:
the Host lease reader requires `$OUT/source.json`, while this workflow only
writes `$OUT/source-before.json`. The actual missing-file error is retained in
`FRESH_SOURCE_FAILURE.json`. This specific failure supplies no fresh-service
performance result.

The workflow now copies the already verified `source-before.json` bytes to the
canonical `source.json` before the source step can succeed. Both files remain in
the artifact. The existing lease reader re-verifies the event-bound source and
ordered merge against actual Git objects and tracked bytes. No fallback name,
new authority, cached acceptance decision or relaxed source check is added.

## Bounded local replay

`replay_workflow_inputs.py` extracts the actual old and new count validators and
the actual fresh-job source-preparation prefix. It replays the six observed
summary lines, retains the old count failure, and exercises the corrected exact
counts plus six refusal mutations. It then creates real small Git head and
ordered-merge fixtures, executes both workflow preparation prefixes and invokes
the unchanged real lease source reader. The old path fails, the copied receipt
passes, and wrong source SHA or changed tracked bytes remain rejected.

All **16 conditions** match their expectations. `replay/RECEIPT.json` binds the
exact script, inputs, command lines and outputs. Host provisioning, the audit
command after that preparation prefix, Rust/native execution and performance
qualification are outside this replay. Optimized Python mode is refused.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  qualification/w1-workflow-native-inputs-20261103/replay_workflow_inputs.py \
  --output /absolute/path/to/fresh-receipt-directory
```

The original two-architecture head/merge factorial matrix and both fresh-service
jobs must run on this successor. The original 4-second/16-hostile service gate,
30-second campaign and production W1/security gates remain independent and open.
The separate #699 campaign's three baseline confirmations and zero pressure
confirmations are not changed by these workflow repairs. DRAFT / HOLD_NO_GO /
DENY_ALL remains in effect.
