# C2 readiness correction and bounded publication observations

The exact source is commit `0e554f36ffdde3053a5eb1756eb5e526b1935032`, tree
`753cdbad6714f00d8ccb9ddbb47f0fd71280ee62`. This packet preserves different
observations separately: a cloud run with missing GNU time, a complete desktop
71-test result, an incorrect inventory command and its correction, one normal
push, a failed CLI body update and successful REST correction, and a bounded
hosted status readback. It is not an all-green CI or whole-chain PQ statement.

## Why the checker changed

The previous readiness checker bound the complete body of the durable ownership
constructor to an older source digest. The reviewed account-development guard
added two comments and `settings.app.check_account_profile()?;` before namespace
effects. The current constructor body is 20,493 bytes, SHA-256
`e89baea593c5a31e16760c3ad42854d9112775b2e51a8994262f06eee379f1d3`.
C2 binds this exact reviewed implementation. It does not accept the old digest
as a fallback. The durable schema and DDL remain unchanged.

C2 changes three files: the readiness checker, its existing test file, and the
corpus JSON containing two reviewed blob-pin updates. The same 71 top-level test
IDs remain; four subtest mutations reject guard deletion, commenting, ignored
errors, and moving the guard after filesystem effects. Rust source files are
unchanged from C1. The corpus is embedded in Node library/example inputs, so C2
requires its own selected native/Clippy observation.

## Retained results

| Observation | Actual result | Scope |
| --- | --- | --- |
| [Cloud](cloud/README.md) | 71 tests ran: 68 succeeded and 3 errored because `/usr/bin/time` was absent; exit 1 retained | Separate corpus suite of 60 and seven source checks passed; the readiness run remains failed |
| [Desktop readiness](desktop/README.md) | 71 distinct test IDs actually completed successfully with GNU time | The original wrapper has one wrong-path inventory command and remains unsuccessful; a separate three-command correction passed |
| [Publication](publication/README.md) | One ordinary push with the project hook succeeded | `gh pr edit` failed on a deprecated classic-Projects GraphQL field; a separate REST body update succeeded and was read back; no push retry |
| [Hosted status](hosted-pending/README.md) | At `2026-11-11T05:29:16Z`, required-baseline run 42964980662 remained pending and returned no jobs | This bounded observation establishes no C2 hosted readiness pass or later final status |

The original desktop wrapper's `all_commands_passed=false` remains in its raw
summary. The correction points to the actual inventory script and retains the
original 71-test observations; it does not rerun those tests or rewrite the
original failed summary. The combined required publication checks are recorded
as a composition of those two observations.

Each child directory includes its original archive, receipts, checksums and
verification instructions. The child packets are unchanged by this index.
The [native packet](../pq-closure-native-observations-20261111/README.md) records
the separate C2 execution source and selected native/Clippy result. The
[dependency readback](../pq-closure-dependency-readback-0e554f36ff/README.md)
records the bounded mapping of seven existing alerts without a complete
vulnerability-scan claim.

Every C1 result keeps the C1 commit/tree; none is relabeled as execution of C2 or
the later evidence commit. Whole-chain PQ qualification, production activation,
and public operating qualification remain unestablished.
