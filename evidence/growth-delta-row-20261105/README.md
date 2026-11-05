# Growth delta row decoding regression

The baseline is integration candidate `2ef9e2fa1985881721a1bff4d546a1b2bdc5ae47`.
This is a local component regression repair, not PQ qualification or production
activation. The original native Growth test and all its assertions are unchanged.

The native delta reader previously deserialized each before/after JSON value,
allocated a single-row State, ran the complete-State account traversal and
allocated another account map to recover that one row. Admission's two changed
accounts require three such row decodes (one before, two after), in addition to
the two required successor-proof State traversals. The complete-State traversal
counter therefore observed `(5, 9)` against the original `(2, 6)` contract.

The repair extracts the existing strict account-row grammar into one shared
function. Complete-State traversal still counts and validates every visited row;
native delta decoding calls the same strict row function directly, without the
temporary State/map scans. It does not cache validation, skip delta JSON parsing,
remove successor checks, or change instrumentation or the original assertion.
The native reader still checks actual parent values, nonce monotonicity, account
count, aggregate balance, duplicate paths, root and stored graph checks.

A differential regression compares native row decoding to the previous
single-row State path, including malformed JSON, neighboring/non-account keys,
ASCII suffix mutations, non-ASCII/uppercase/incorrect-length owners, malformed
values and the u64 boundaries. Existing prefix-versus-complete-scan tests remain
an independent copy of the old parser grammar.

The unchanged native Growth test exercises zero/64/4096 unrelated working rows,
256 dormant accounts, both successor proof callbacks, complete-state roots,
receipts, durable reopen, balances and old-nonce rejection.

No schema, signed domain, budget, public-service qualification or activation
flag changes. Full same-head x64/arm64 PQ network/rollback and unrelated business
acceptance remain separate gates.

## Observed verification

- Baseline [native failure](baseline-failure.log): 0 passed, 1 failed,
  `(5, 9) != (2, 6)` at the unchanged admission assertion.
- Repaired [account-prefix suite](account-prefix-green.log): 4 passed,
  0 failed, 1 pre-existing ignored component benchmark; all four original native
  Growth cases report `make=(2,6)` and `admit=(2,6)`.
- Initial exact-source guard failures are retained in
  [source-pin failure](initial-source-pin-failure.log) and
  [workflow-pin failure](workflow-pin-failure.log). The two changed Rust blobs
  and the workflow that pins them are repinned to their actual new content.
  No guard or acceptance condition is removed.

Rust 1.95.0, original checked-in Cargo test profile, locked dependencies,
x86_64 Linux; native tests above use default features. These observations do not
replace the full optional-PQ-feature x64/arm64 network/rollback workflow or the
original fixed-Host business acceptance. No service-performance claim follows
from shared-cloud test execution.

Additional observed checks, before publication:

- [Native store](native-store-green.log): 7 passed, 2 pre-existing ignored
  diagnostics, including 2,603 differential row-decoding combinations.
- [Native primitives](native-primitives-green.log): 11 passed, 3 pre-existing
  ignored diagnostics; complete old account grammar, graph corruption,
  cancellation and rollback checks remain exercised.
- [Growth storage](growth-storage-green.log): 52 passed, 2 pre-existing ignored
  explicit scale observations. Fault, recovery, reorganization, epoch and
  proof-cancellation tests ran with `RUST_TEST_THREADS=1`.
- [Strict Clippy](clippy.log): `-p trnm-pon-node --all-targets --all-features --
  -D warnings` passed. The system OpenSSL is 3.5.7; this is not the workflow's
  independently pinned OpenSSL 3.5.9 runtime qualification.
- [Source-integrity controls](source-integrity.log): 43 passed.
- [PQ source controls](pq-source-tests.log): 35 passed; the
  [487-blob check](pq-source-check.json) retains `HOLD_NO_GO` and all false gates.
- [Repository check](repository-check.json): 26 packages, 1,146 Rust files,
  2,978 existing links passed before this evidence folder was added.
- Full workspace formatting, locked Cargo graph and unchanged lockfile passed.

The native test totals are 74 passed and 8 pre-existing ignored tests across
these four selectors, not an all-workspace test pass. Raw logs retain their
original source-state/checkpoint labels; publication does not relabel the dirty
candidate repository receipt as a committed-source result.
