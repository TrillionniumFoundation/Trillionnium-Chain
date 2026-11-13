# Chain PR #909 — terminal hosted CI snapshot

Observed on 2026-11-12, 06:00:57–06:08:30 UTC. This is a read-only review of three existing completed runs. No workflow was rerun and no code, branch, PR, credential or host state was changed.

## Source binding

- PR head **e338c000f26e9357ed33213624da787a3a009ed9**, tree **876aa62d1ab49458d29e9168f4c69e7b47b8884b**.
- Actual prospective merge **bfa5cf58953a67dd9b9a27ce52b63524933a029d**, tree **4b08c77fd511466c8f2e5bc46307e0d6fd629063**. Its parents are PR base **c84162378f34b9284e90587df4c466dfee3e193b** and the above head.
- Every failed job that checked out source has its actual `git log -1` and original source-verifier receipt retained in INDEX.json. Run-level `head_sha` does not replace those records.
- The historical-artifact job has no checkout. The two cancelled macOS jobs have no observed checkout or execution log.

In the tables below, **H** means the exact PR head and **M** the exact prospective merge above.

## Workflow outcomes

| Workflow / run | Final status | Job conclusions |
| --- | --- | --- |
| [PoN priority acceptance / 43030977438](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977438) | failure | 7 failure, 6 success, 1 skipped |
| [trnm-required-baseline / 43030977601](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977601) | failure | 11 failure, 10 success |
| [PoN owned process cleanup / 43030977513](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43030977513) | failure | 6 success, 2 cancelled |

These are job counts, not test counts. Success metadata was retained; unrelated successful-job logs were not reread.

## What actually failed

| Jobs and source | First failure established by the original log | Classification and limit |
| --- | --- | --- |
| Priority 130582693678; no checkout | `actions/download-artifact` requested artifact **11531476198** from historical run **37730166589**, found zero artifacts and failed. | Historical evidence retrieval failure. The cause of the artifact's absence is unknown; the earlier failed run is not reclassified. |
| Priority service-model: **H** 130582694482, 130582694747; **M** 130582694472, 130582694530 | “Execute original release from-zero controls” exits 1. Original host-controller summary says `passed=false`, `systemd_run_exit=1`, `failure=null`, `final_host_errors=[]`. | Actual child failure, but the child assertion/stderr is not present in this job-log summary. No product/environment root cause or timeout is inferred. Later successful negative controls containing caught panic text are not counted as failures. |
| Priority history: **H** 130582694631; **M** 130582694539 | “Execute 4105 real work blocks and paid public full sync” exits 1 with the same host-controller result shape. | Both failed jobs are x64 lanes. The actual history child failure is not exposed in the public job summary. ARM history jobs are success in metadata; results are not added together. |
| Baseline cross-arch: **H** 130598327693, 130598327905; protocol-contract: **H** 130598327819, **M** 130598328085 | The original from-zero control command exits 1, again `systemd_run_exit=1` with no host failure detail. | The earlier protocol groups printed success, but the overall protocol jobs fail at from-zero. Artifact listings are retained; ZIP payloads were not downloaded. |
| Baseline quality: **H** 130598327708; **M** 130598327796 | `dependency policy refused one or more graphs; inspect retained diagnostics`; retained `supply-chain` result `FAIL`; exit 1. | Dependency-policy gate refusal. The graph/advisory details are not printed in this log, so no specific dependency or vulnerability is asserted. |
| External-evidence-contract: **H** 130598327976; **M** 130598328088 | `check_public_readiness_evidence.py:501` rejects `sha(selected_body.encode()) == reviewed_bodies[observation_field]`: `ValueError: durable backend selected implementation`. | Source/reference hash gate. Each repeated unittest invocation reports **71 methods, 46 failures, 22 errors**. Many negative controls receive this earlier error instead of their intended later schema error. This is not 68 independent causes, and the two invocations are not summed. No baseline test or source comparison here proves which source/reference should change. No hash was refreshed. |
| Prospective runtime: **M** 130598328213 | `ordinary_npq6_witness_selection_dispatches_account_packet_without_owner_downgrade` panics at `crates/trnm-pon-node/tests/pq_parent_npq6_cli.rs:244:14` by unwrapping `Transport / Connection reset by peer (os error 104)`. The binary reports **5 passed, 1 failed**; Cargo exits 101. | Real merge-source native test failure. The server-side reset cause is unresolved; it is not declared environment-only. **Head runtime job 130598327706 is success in the original jobs metadata**, so this merge-only failure is not attributed to H. |
| Rust aggregation: **H** 130669194540; **M** 130649216164 | `ValueError: every Rust shard job must succeed`. | Expected aggregation refusal after failed shard jobs; not an additional independent native failure. |
| Cleanup macOS: 130557620566 prospective, 130557620949 head; no observed checkout | Jobs metadata says `cancelled`, zero steps, `runner_id=0`, blank runner name. Both formal log downloads return **404 BlobNotFound**. | Cancellation reason and any execution are unestablished. The connector rejects check-runs GET as unsupported; no alternate access bypass was attempted. The six other cleanup jobs are success in metadata. |

## Evidence preservation

INDEX.json contains all job identities, exact source receipts, failure excerpts/line numbers, raw response paths, and an ordered per-log byte manifest.

- **10 exact API JSON bodies:** three runs, three complete job lists, two artifact lists and both Git commit objects.
- **18 complete failed-job decoded logs**, preserving all BOMs, timestamps, ANSI characters, line endings, giant JSON lines and meaningful whitespace. They are retained in **40 ordered parts**, not abbreviated excerpts.
- **5 original tool-return records serialized as JSON:** the first baseline jobs read timeout, both macOS 404 responses and both rejected check-runs reads. These are retrieval results, not native failures.
- **55 evidence paths / 54 unique Git blobs**, totaling **11,432,039 bytes**. Every blob is at most **380,402 bytes**, so no global blob-size limit or allowlist change is needed for these objects.
- Each part was hashed as exact UTF-8 bytes before upload. Every create_blob result equals its computed Git blob ID. Concatenation without separators reproduces each entire decoded log, with whole length/SHA-256/Git ID in INDEX.json.
- This preserves the connector's decoded log bytes; it does not claim preservation of the temporary redirect's original ZIP or HTTP wire representation. API body strings were uploaded without parsing and reserialization; error objects are explicitly labeled serialized tool returns.
- No branch was created or moved. Suggested destination is `qualification/chain-pr909-final-ci-20261112/` on Root's separate evidence branch, keeping PR909's tested code head fixed.

## Acceptance boundary

The earlier structure/closure/work-time/large-state/workspace-profile successes remain their own evidence. They do not establish a fully green repository. Existing CodeQL evidence was not reread or reclassified.

These runs establish no ordinary A-to-C business closure, no independent C consumer adoption, and no ordinary NoUpdateRollback. The report does not add duplicate matrix invocations, caught negative-control panics, shard aggregation failures or earlier local test counts.
