# Exact 2a69 hosted W1 receiver readback

This is a **selected extraction of an actually completed hosted run**, not a local rerun, new proof generation, whole-project qualification, or qualification of a later commit. No source, workflow, or sole plan was changed to obtain these results.

- Tested commit: `2a69a989046489c212619dd337ee74a083f101de`.
- Tested tree: `e6d2e1d84e0ce7eae374fc635f79179026653545`.
- [Workflow run 41159178283, attempt 1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178283): success, completed 2026-10-31 02:35:50 UTC.
- [Job 124412661337](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178283/job/124412661337): `exact host and real historical W1 cases (research only)`, x86_64 Ubuntu 24.04, pinned Rust 1.95.0.
- [Artifact 13026678580](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41159178283/artifacts/13026678580): `w1-audit-one-2a69a989046489c212619dd337ee74a083f101de-1`, 15,939,362 bytes, SHA-256 `b8f026fe9f73132f26d4c5a76d967e364c15f0616fdc574bf1c0d7e00223a63c`. The downloaded ZIP size and digest match GitHub's metadata.

## Actual results

Both source guards verify the exact commit/tree and tracked worktree. All 17 source-input hashes reported by the native audit were additionally matched to immutable Git blobs at that commit during packaging. The hosted verifier hash is `9be52c6ea348052c09bc6c74504017ad34c7bcd9df9e1563f3fd1fc510afbc36`; its archive member matches all three hosted before/after hash records.

- Native host stdout: **21 passed, 0 failed**. Release/locked host and relation all-target Clippy with `-D warnings` returned 0. The enclosing build step also successfully ran the workflow's fmt check; fmt has no separate process JSON.
- Fixture controls: **39 passed**; existing case-reader controls: **15 passed**; new public-claim-reader controls: **8 passed**.
- Original complete audit: the real proof positive control passed and **all 16 mutations were rejected**. All original negative-case details remain in `selected/original-audit.stdout.log.gz`.
- All eight fixed cases returned the expected native outcome and each hosted independent reader reported successful metadata/byte bindings and 17 checked sources.
- Public-claim experiment: **six cases × four paired route/context observations = 24**. The hosted reader reports `metadata_bindings_pass=true`; its explicit limits remain in the original record.
- All 14 archived measured child processes returned 0 without timeout. No failed or skipped experimental phase is being hidden behind the successful workflow status.

### Eight fixed cases

These are single receiver observations after each process's real-proof positive prerequisite. They are not medians or end-to-end ingress timings.

| Case | Actual native result | Receiver total, ms |
| --- | --- | ---: |
| `valid` | accepted | 1247.220653 |
| `first_seal_tamper` | rejected | 31.701576 |
| `last_seal_tamper` | rejected | 1243.680009 |
| `wrong_verifier_parameters` | rejected | 29.640575 |
| `wrong_statement_miner` | rejected | 29.611199 |
| `truncated_receipt` | rejected | 0.015279 |
| `trailing_receipt_bytes` | rejected | 0.013765 |
| `seal_length_allocation_bomb` | rejected | 0.004247 |

### Public-claim experiment

All times below are **receiver totals in milliseconds**, rounded from retained integer nanoseconds. “Reference” is the original SDK ordering within the same candidate executable, not an independently built old binary. “Fresh” means a fresh prepared verifier context, not cold hardware. Prepared reusable-context setup was **18.661698 ms**, recorded separately; fresh-row context setup is included in that row. The positive prerequisite cost was **1,270.173818 ms**, outside the row timing.

| Case | Reference, fresh | Claims first, fresh | Reference, reused | Claims first, reused |
| --- | ---: | ---: | ---: | ---: |
| `valid` | 1255.912 | 1251.215 | 1235.534 | 1230.373 |
| `outer_journal_rebound` | 1229.897 | 22.741 | 1212.709 | 4.127 |
| `late_link_tamper` | 1230.038 | 22.772 | 1212.030 | 4.189 |
| `late_nonfinal_exit` | 1211.079 | 22.905 | 1192.261 | 4.188 |
| `matching_claims_corrupt_seal` | 1231.243 | 1229.120 | 1211.443 | 1210.514 |
| `coordinated_public_claim_forgery` | 1232.148 | 1229.542 | 1211.162 | 1213.400 |

Only `valid` was accepted. The three inconsistent-public-claim cases were rejected before entering the full SDK on the new route. `matching_claims_corrupt_seal` and `coordinated_public_claim_forgery` still entered the full SDK and were rejected, retaining approximately 1.21–1.23 seconds of receiver cost in this observation. **Worst-case rejection cost remains open.** Valid proofs still require the full SDK.

## Historical fixture and scope

The proof is the pinned historical **15,862,780-byte Composite receipt with 62 segments**, SHA-256 `0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8`. It is not the separate 256,886-byte Succinct experiment. Fixture provenance remains historical run `40608715148`, artifact `12784520070`, source `a54dc7355f58f40784b5a71fe7e73c4062a14951`, as retained in `fixture-binding.json`. This run restored and checked the durable objects; it did not download/reverify the original historical ZIP or generate a new proof. Current test-source identity and historical proof provenance are distinct.

The public-claim reader checks source/byte bindings, fixed schema and recorded outcomes. It explicitly does **not** independently reverify the cryptographic proof, reconstruct all SDK mutations, or remeasure timing. The native verifier performed the proof checks in the hosted job. No verifier, native test, or reader was rerun locally during this readback.

The host is not exclusive; the prerequisite warms the runtime. This is one fixed historical statement and single paired observations, not a statistical benchmark, fresh-challenge distribution study, native W1 replay benchmark, or network-ingress campaign. Recorded receiver scopes exclude file I/O, prerequisite verification, case construction, source/byte hashing, formatting, process startup and, for the claims experiment, statement binding. Preserve the exact scope arrays in the raw JSON when interpreting costs.

Minimum work hardness, public ingress, throughput, practical full-proof economics, PQ128 security and production/consensus authority remain unqualified. No result is relabeled to a later head, and no prior failed gate is promoted to passing.

## Contents and byte preservation

`selected/` contains all 63 selected small original artifact members. Log files and large payloads use deterministic lossless gzip; decoded bytes were independently compared with the corresponding ZIP members. The full ZIP, verifier and three fixture binaries are omitted from this package. Their actual archive-member hashes are retained in `selected-artifact-manifest.json`.

The job log preserves the exact UTF-8 **provider-decoded log text**; raw HTTP log-archive byte identity is not claimed. Run/job/artifact metadata are normalized GitHub plugin snapshots, not raw HTTP response bytes. `summary.json`, `byte-verification.json`, this README and the packaging manifest are derived readback records. `workflow-at-head.yml` contains the exact immutable workflow Git blob. `manifest.json` binds every packaged payload by size and SHA-256 and labels the source category.
