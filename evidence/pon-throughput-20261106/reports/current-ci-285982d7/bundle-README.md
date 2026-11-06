# Original CI observations for 285982d7

Snapshot: **2026-11-06 09:28:59 UTC**. Candidate `285982d78a4f62a064841cb0f106d18c865e19c5`, tree `ce074eb1857a92c9b47ea317b841777fcfc63c04`. Every run is original attempt 1; no rerun or cancellation is substituted for earlier evidence.

| Workflow | Original run | Terminal conclusion |
| --- | --- | --- |
| native_campaign | [42185197057](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197057) | failure |
| f0 | [42185197083](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197083) | failure |
| large_cpu | [42185197106](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197106) | success |
| workspace | [42185197125](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197125) | success |
| pq | [42185197027](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42185197027) | success |

The campaign remains failed: all three baseline first confirmations took 21.205759120 / 21.203138983 / 21.305650019 seconds, and each attack phase had zero confirmations. F0 remains failed: **0/6** planned slots met the four-second SLO; its one baseline confirmation arrived after **24.901798841 seconds from the scheduled slot** (24.901311617 seconds from actual start), and ROOT had no confirmation. These are finite native fixture observations, not real-difficulty WAN confirmation times or production TPS.

The original large-state CPU workflow has four successful matrices, four named native controls each, on the explicitly seeded 8,625,548-byte custom-genesis fixture. Workspace has four matrices with actual **80 passed / 0 failed / 0 ignored** selected controls, plus the original four CPU/public-loop controls. Registry selection alone is not counted as execution. Growth remains a finite local observation; its cold recovery costs and false public/throughput qualification flags are preserved in the raw records.

## Actual complete Node-library summaries

| Original artifact | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| pq-system-ubuntu-24.04-prospective-merge-285982d78a4f62a064841cb0f106d18c865e19c5-1 | 1172 | 0 | 32 |
| pq-system-ubuntu-24.04-arm-prospective-merge-285982d78a4f62a064841cb0f106d18c865e19c5-1 | 1172 | 0 | 32 |
| pq-system-ubuntu-24.04-arm-head-285982d78a4f62a064841cb0f106d18c865e19c5-1 | 1172 | 0 | 32 |
| pq-system-ubuntu-24.04-head-285982d78a4f62a064841cb0f106d18c865e19c5-1 | 1172 | 0 | 32 |

The complete harness summary is the last one in each Node log. Three filtered child harness results are not added to it. The 52 native, 14 TLS/ordinary-binary, 13 scope and full-library suites overlap and must not be summed as unique tests. Primitive/SDK observations do not grant whole-chain quantum-security acceptance.

## Budget and provenance

All 44 actual before/after inside/outside Host snapshots retain `/sys/fs/cgroup/trnmponpublic.slice`, CPU `25000 100000` (0.25 CPU), CPU burst 0, memory 2,147,483,648 bytes, swap 0 and 256 tasks. Campaign and F0 controller before/after snapshots retain CPU `400000 100000`, memory 17,179,869,184 bytes and nice 10; this separate external-actor/controller allocation does not enlarge the shared public receiver/verifier Host.

Host checkpoint CPU is nested within caller CPU. It must not be added to caller CPU, and a missing telemetry cohort is unknown rather than zero. Similar runner models and equal cgroup limits do not establish a controlled cross-run performance comparison. The F0 hardware record does not include CPU model.

`primary-api/status-and-run-job-records.json` retains primary run/job API records with individual retrieval UTC timestamps; `manifests/artifacts.json` retains original artifact IDs, full ZIP SHA-256/size and source identity. Small selected archive entries are byte-exact, with entry digests. Raw giant telemetry, ZIPs and ELF files are omitted, and remain retrievable from their original artifacts subject to GitHub retention. Every included file is covered by the file manifest; all complete terminal job logs are included.

The old b173 failures, the old 9e50 four-matrix 79/80 and 1169/1/32 failures, and the 1986 conflict-blocked zero-run observation remain separate. The old final evidence archive is `final-evidence-20261106T081354Z.zip`, 5,191,414 bytes, SHA-256 `a109fc9f1941f66e135eba717e61144a6e4ad0aa4cc888ee3d6d4f5e16c06a35`; this later bundle does not overwrite it. No code, source pin, workflow, threshold or branch is changed by these readers.
