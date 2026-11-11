# Current W1 lifetime source survey: 2026-11-11 quantum/DAA maintenance

This directory contains a deterministic source-survey fixture, prepared from the
twenty selected source files at Git commit `2582a6d15a14d3929d3238d844e710f5a291b422`.
It is source data and declared research output, not a Python execution receipt,
a hardware measurement, a new cryptographic proof, or a qualification decision.

## Scope and preserved history

The earlier [2026-11-09 report](../pon-w1-lifetime-current-20261109/project-report.json)
remains unchanged. Its source anchor is
`189b9b5959d836ef6ae96e14fb285948e4920aa9`; all twenty original source
digests were read back and matched at that commit.

All twenty sources were also read back at the new anchor. Eighteen have the same
bytes. The two reviewed differences are:

| Source | Change from the earlier source survey | Current SHA-256 |
| --- | --- | --- |
| `trillionnium/crates/trnm-pon-node/src/consensus.rs` | Test-only arithmetic vectors inherited through base `e4abb172147e941b62483652b0ceabaae4317624`; the production prefix before the test module is unchanged. | `dbbd44790428ae0aff32d7305e062a6fc09ca0add0e3c4c077deefd8bfec760d` |
| `trillionnium/crates/trnm-pon-node/src/store.rs` | The existing `check_observed_history_with_progress` helper becomes `pub(crate)`; its body is unchanged. | `f3f67de052d2f33fb0e0060d7ba5cd1c9912a7eff64a837aa0e396cdb80808d1` |

The twenty-path roster is selected coverage. It excludes the public ingress
dispatcher `trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth.rs`,
its `growth/tests.rs` tests, and the quantum network simulator. It is not a
complete runtime or consensus dependency closure.

## Exact preparation rule

Starting from the unchanged earlier JSON report, preparation updates only:

- `selected_source_survey.base_commit`;
- the SHA-256 and byte length of the two changed source records;
- the SHA-256 of the four observations referring to those source records.

The four observation line numbers remain unchanged. No other report value
changes. The report retains schema `TRNM-W1-LIFETIME-LEDGER-REPORT1` and status
`CONDITIONAL_ACCOUNTING_AND_SELECTED_SOURCE_SURVEY_SECURITY_HOLD`.
All project query budgets, error bounds and security bits remain unknown;
all acceptance and production qualification flags remain false.
`whole_repository_build_or_behavior_verified` remains false.

The current [project report](project-report.json) has SHA-256
`9945fe2ccf491d8f91b05df40903c2979700a729ddb913f576043941e4b80a37`.
The prior report has SHA-256 `8ee20462d669a0e21b0fe964585f85fa2a49e7e58273459ab2501b4a2e39dfc0`.

## Required independent execution

The fixture was prepared by an explicit structural transformation and checked
against retrieved Git source bytes. That preparation does not claim that Python
executed. CI must independently recompute the report with the updated reader and
compare the complete bytes, using the existing nineteen-test suite:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/test_w1_lifetime_ledger.py
```

The suite recomputes `make_report(template(), ROOT)`, compares it byte for byte
with this fixture, reads all twenty files from `SOURCE_BASE` with replacement
objects and lazy fetching disabled, and checks those bytes against the working
tree. The named W1 closure controls also run the suite. An execution result is
valid only for its recorded commit and must be retained separately; this README
and fixture contain no new execution-success claim.

The isolated W1 implementation contract's inherited fixed-source mismatch
(`w1_v2_verifier/src/main.rs`, 9,233 declared bytes versus 11,172 current bytes)
is a separate unresolved observation. This maintenance does not change its
fixed-source contract, input limits, or security qualification.
