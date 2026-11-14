# Component runner review

The local Python runner controls passed **14 tests** with exit code **0**.
This checks the new component lane's transcript validation, source refusal,
compiler-artifact/profile binding, and complete stdout/stderr capture.
Constructed native transcripts and JSON records are reader fixtures, not
observations of a Rust test, W1 execution, CPU deficit, or confirmation campaign.
The capture test starts a small Python child only.

The source context was b7e38fdc2e43c468692abc52aec03737f2df7f1b.
The three new workflow/runner/test files were still uncommitted during this
review. Their exact input hashes were checked before and after the Python run;
the recorded committed_source_binding remains false. This result must not be
relabeled as native execution on a later committed source.

## Retained observations

- [final-review.json](final-review.json): original local review record, input
  sizes/hashes, exit code, and unchanged false qualification fields.
- [inputs.sha256.txt](inputs.sha256.txt): repository-relative SHA-256 entries for
  the three new files and the three imported existing validation helpers.
- [runner-controls-final.stdout.txt](runner-controls-final.stdout.txt): complete
  original stdout; it is empty.
- [runner-controls-final.stderr.txt](runner-controls-final.stderr.txt): complete
  original unittest output, including all 14 test names and the final result.

The JSON record names the original captures without the final .txt suffix.
The retained .txt files contain exactly those same bytes and match the hashes
in the record. No failed or partial native observation is replaced by these
Python results.

Reproduction command, from the repository root:

    python3 -B scripts/ci/test_pon_budget_controls.py

The new Actions lane still has to build the exact Rust 1.95.0 release libtest,
retain its actual test list and binary, and execute all seven controls on both
sources. Its old-source arm requires six specific assertion failures and one
packet-equivalence pass; a fixture that never reaches the real M06 CPU deficit
fails that arm. The current-source arm requires all seven passes. Both remain
component checks only. Original campaign and throughput qualifications, budgets,
timeouts, and existing gates are unchanged.
