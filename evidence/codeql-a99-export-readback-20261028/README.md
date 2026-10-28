# Exact-source CodeQL export and warning-location readback

The original exporter completed successfully in **740.911364 seconds**, inside its unchanged **1,200-second** limit. It exported the API-available Actions, Python and Rust analyses for exact source `a99ef8e333b6f1b7486b33e820464cf824fec273`, PR **#533**, base `9fedf7ecbbe07177069c030592b4e03dcffebb81`. No workflow, security predicate, timeout, permissions or analyzed repository source was changed by this readback.

- Export run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40623893027
- Export job: `122604116776`; original artifact: `12788613489`.
- Original ZIP: **280,064 bytes**, SHA-256 `6e6f9b6545f288dd90a5c83d1158a96d1342da0e593689e39cfb1de23c3c818f`.
- All **145** ZIP members were actually read, CRC checked and hashed. The outer **143**-entry and inner **139**-entry manifests have exact file sets and matching hashes.
- Source before and after is identical: tree `f996fa2ad8cfa4426b6a7b2e04c5fd858025f8fe`, **5,959 tracked entries / 767,617,754 bytes**.

## Why the exporter waited

The delay was the existing analysis and stability gate. Polls 1–5 had no selected analysis; poll 6 had Actions, while the source check reported two missing configurations. Polls 8–22 had Actions and Python, while Rust was still missing. Rust analysis `2041935511` was created at **03:09:37 UTC**. Polls **23**, **24**, and the complete post-export read all contain the same analysis/check state. The independent offline reader compares those full objects, not just their success booleans.

| Language | Analysis ID | Rules | API SARIF results | Created UTC |
|---|---:|---:|---:|---|
| Actions | 2041899112 | 17 | 0 | 03:00:45 |
| Python | 2041904174 | 43 | 0 | 03:02:03 |
| Rust | 2041935511 | 26 | 322 warnings | 03:09:37 |

All three are CodeQL **2.27.3**, on the exact source and `refs/pull/533/head`, without analysis error/warning metadata. Source check **122605175751**, app **57789 / github-advanced-security**, is actually completed/success and explicitly associated with the exact PR head/base. Its title is “No new alerts in code changed by this pull request.” Its zero annotations are not evidence of zero repository alerts.

The exporter intentionally records `target_pr_gate_authenticated: false`, `target_pr_gate_verdict: null`, `full_original_sarif_upload: false`, and `all_branch_historical_alerts: false`. This readback preserves those limits. The archive contains the API SARIF subset, not the complete analysis database, all historical alerts, or a proof that every security condition is satisfied.

## All 322 warning locations

The independent source triage matched all **40** affected files against the exact a99 Git blob identities and SHA-256 of their actual bytes. Both complete recursive Git trees are retained: a99 tree **6,593 entries** and main-base tree **1,267 entries**, neither truncated. The table counts SARIF results; repeated locations with separate flows remain separate results.

| Source scope | Results | Meaning |
|---|---:|---|
| Explicit tests/fuzz files | 228 | Test or fuzz targets |
| `#[cfg(test)]` modules inside otherwise runtime source files | 88 | Exact module ranges recorded and checked |
| Examples or research fixtures | 5 | Three cleartext-logging and two hard-coded-value locations |
| Runtime CLI output | 1 | `trnm-pon-node/src/main.rs:2610`, `rust/cleartext-logging` |
| Total | 322 | 299 `rust/hard-coded-cryptographic-value`; 23 `rust/cleartext-logging` |

There are **316** test/fuzz results, **5** example results and **1** runtime result. No finding was suppressed, removed, reclassified in CodeQL, or automatically declared a false positive. The category describes where the reported source exists; it does not establish the severity of a data flow or the absence of secrets elsewhere.

### The actual runtime result

The exact primary location is `trillionnium/crates/trnm-pon-node/src/main.rs:2610`, in `fn main`, where successful `run()` output is printed as `value`. The API SARIF supplies **four** flows spanning four source files; all paths/line regions, without snippets or sensitive values, are retained in `runtime-flow-locations-no-snippets.json`.

The examined flow includes these concrete symbols and locations:

1. `account_archive_prototype/native_store.rs:137–154`: `lookup` receives `owner: Hash`, derives the account-tree traversal `key` with `super::path(owner)`, compares it to a stored owner, and returns an `Account`. That variable is an account-tree key derived from the owner hash, not an observed private signing-key variable.
2. `account_archive_prototype/native_store.rs:264–301` and `store/growth/recovery.rs:182–197,290–295`: account lookup and growth application feed the returned account/state information. The original SARIF paths are retained rather than shortened to the primary sink alone.
3. `growth_cli.rs:257–265`: `node.growth_account(block, owner)` and `node.growth_account_multiproof(...)` build query responses containing owner/account or checkpoint/proof/observation material. Another reported flow traverses growth admission at `growth_cli.rs:280`.
4. `main.rs:1301` returns `growth_cli::run(&command, &args)`; `main.rs:2607–2610` prints the successful result.

In the examined source, the identified inputs are owner hashes and account/state/query data. This review did **not** establish a private signing-key source in those four flows. It also does not independently certify every query field's confidentiality. The runtime finding is retained for an owner to confirm the intended output policy; calling it a confirmed key leak or claiming zero runtime warnings would both exceed the evidence. No literal key or sensitive value is reproduced in this report.

### The five example results

- `examples/support/state_witness_artifact.rs:234,283`, `rust/cleartext-logging`: invalid state-witness fixture removal/insertion paths.
- `examples/lifecycle_atomic_continuity.rs:328`, `rust/cleartext-logging`: mutation of an invalid-transaction example fixture.
- `examples/pon_w1_budget_report.rs:257`, `rust/hard-coded-cryptographic-value`: the fixed challenge nonce selected for the deliberately false-trace producer.
- `examples/llm_zero_gain_round.rs:242`, `rust/hard-coded-cryptographic-value`: initialization of a salt buffer that the next line fills through `read_exact` from the operating-system random source before later use.

These are source observations, not blanket false-positive decisions. Exact source hashes and complete result locations are retained for review.

## What was introduced by this change

The latest **a99** commit changes **48** files, covering the legacy-layout reader, its lexical tests, documentation and evidence. It changes **none of the 40 files containing these 322 warning locations**. Its exact changed-file roster is included in the provenance record.

PR #533 as a whole spans a much broader **649-commit** difference from main. Relative to exact main base `9fed...`:

- **119 results / 3 files** have identical whole-file Git blobs at head and base.
- **49 results / 3 files** are in files whose blobs changed: `trnm-types/src/relay.rs`, `trnm-worker-agent/src/workflow_ops.rs`, and `trnm-research-protocol/tests/protocol_v1.rs`. Exact source reads map **37** of their reported line spans to unchanged line text in the base. That textual mapping does not establish unchanged data flow for those results; the other 12 unmapped spans are not automatically 12 newly introduced alerts.
- **154 results / 34 files**, including the CLI output location, are in files absent from that main base. This establishes branch-vs-main source presence, not which of the 649 commits introduced the behavior or when CodeQL first reported it.

No baseline SARIF comparison or alert-history API was used to assign first-introduced dates. The incomplete, 3,000-file-capped PR-files endpoint was not used to claim that an omitted file was unchanged; the complete Git trees resolve that issue.

## Reproduce this readback

`original.zip` is the original artifact byte for byte. The unmodified exporter and workflow sources are included as `export_codeql_analysis.py` and `codeql-analysis-export.yml`; their original paths are `scripts/export_codeql_analysis.py` and `.github/workflows/codeql-analysis-export.yml` at exact a99. The original job log, API terminal metadata, all member hashes and both complete compressed Git inventories are retained.

Run `python3 independent_verify.py` for offline ZIP/manifests/source-record/stability/analysis/check/location checks. Add `--source-root /path/to/exact-source` to verify all 40 actual affected source files. `triage_warnings.py /path/to/exact-source` reproduces the location categories and base-line text mapping from the retained exact comparison input. Both readers use only Python's standard library and perform no native admission, proof generation or repository-source mutation.

The final recorded run passed with all 40 exact source files. Small development errors in the new triage script were fixed before that final run: a closing-bracket syntax typo and the assumption that two test modules ended at EOF (they actually end before subsequent public module declarations). These were reader-development errors, not changed source, ignored scanner results, or changes to the original exporter gate.
