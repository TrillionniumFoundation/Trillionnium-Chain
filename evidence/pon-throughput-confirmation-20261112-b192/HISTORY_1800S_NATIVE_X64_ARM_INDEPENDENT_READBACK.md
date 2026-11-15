# PR #890: independent native History 1800-second service-lifetime contrast

**HOLD_NO_GO / observation only.** This audit binds to exactly tested commit `b192712ca096c79766d3570fc4fa224da68d026d`, tree `4d83903ad3afae867343a1207966f14b1e4dd7c7`, stacked base `e4abb172147e941b62483652b0ceabaae4317624`. It does not revise original W1/M06/Host requirements, the 0.25 CPU / 2 GiB / zero swap / 256 PID / 4-second Host gates, any production claim, or the original three 30-second phases and denominator. New evidence-only successors must not inherit native test success.

## Exact original raw sources

- [Required Priority run **43134866221**](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134866221), x64 History [job **130918171699**](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134866221/job/130918171699), [artifact **13917705198**](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134866221/artifacts/13917705198). Independently downloaded ZIP: **53,511,319** bytes, SHA-256 `bc165c91380067d8e124693c82e930a63f34626fc23f0ca052da2a25641071a8`; all **4,140/4,140** members pass CRC, **573,546,374** decompressed bytes.
- Same run, arm64 History [job **130918171829**](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134866221/job/130918171829), [artifact **13917750065**](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134866221/artifacts/13917750065). ZIP: **61,301,091** bytes, SHA-256 `970e2ad6b390dfbb649f9da53a764d35646142621c0a8fb015d6e6ecf7cf3195`; **4,140/4,140** CRC, **644,959,427** decompressed bytes.
- Both `source.json` files name exactly the same head and tree and report verified tracked worktree. Both `history-native/preparation.json` files report completed locked release native compilation with `--no-run` (not a test pass on its own). The two native tests then execute under original Host parent identities and `cpu.max="25000 100000"`, `memory.max=2147483648`, `memory.swap.max=0`, `pids.max=256`.

## New bounded root-cause classification

| Original observation | x64 head | arm64 head |
| --- | --- | --- |
| native test | FAILED / exit 101 | PASSED / exit 0 |
| original 4,105-page native independent sync | failed after **2,788** successful page-import call returns | **4,105** packets confirmed |
| exact failure stage | `history-rpc` | no failure |
| returned error | `IO: Connection refused (os error 111)` | none |
| actual server loop termination reason (original stdout) | `lifetime_expired` | `stop_requested` |
| lifetime reached before shutdown | **true** | **false** |
| configured public server lifetime | 1,800 seconds | 1,800 seconds |
| server observed runtime | 1800.001660108 seconds | 1500.096462383 seconds |
| wall clock for whole native test | 53:30.20 | 50:13.89 |
| original test's independent fullsync progress, 500 → 2500 pages | 1727.6009s → 3019.3958s | 1687.3714s → 2399.2676s |

Both the x64 `history-native/history.log` and `long-history/summary.json` identify the outcome; the same service stdout reports `lifetime_reached_before_shutdown=true` and `reason=lifetime_expired`. The Rust test's server is launched with `Duration::from_secs(1800)` and serves a **one-packet-per-History-page** public flow. The next x64 History RPC failed only *after* service expiry, not due to a demonstrated consensus mis-activation. The arm64 run completed before expiry and explicitly requested shutdown.

The measured progress intervals imply **1.548** x64 and **2.809** arm64 observed pages/second within those local segments. These are *trace-derived, nonqualified rates*, not comparative architecture benchmarks, real business TPS, WAN throughput or evidence that changing machine type fixes production. The environment and system-time conditions differ, and the test itself explicitly declares no production/network/hardness qualification.

**Do not “fix” this by increasing the 1,800-second lifetime, increasing CPU/resources, skipping any public proof/cookie/Host verification, batching around original page limits, substituting fixtures, or reclassifying failed x64 as passed.** Investigate native x64 History RPC/import critical path, including Host checkpoint and resource/CPU attribution, under matched exact-source builds and original resource fences, and separately prove a completed cold client restore and exact request/effect deduplication.

## Complete original business campaign remains FAIL

The same head's [original campaign run **43134865479**, artifact **13912583063**](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134865479/artifacts/13912583063) was independently re-downloaded and verified: ZIP **82,931,128** bytes, SHA-256 `fa4b0f2ce04f1638a404f57628cd549910c56f88981f0646095f1c4bb9e9d355`; **1,765/1,765** manifest hashes and lengths, **657,312,122** decompressed manifest bytes, zero missing/unlisted or CRC errors. Its three original native campaign attempts all actually executed and exited **101**, giving **0/3** passing campaigns, **0/9** qualifying phases, **3/27** in-window planned confirmations. The repeated fixture confirmations cannot be counted as three distinct independently finalized business effects. The second History terminal page, client chain activation, post-timeout cross-process request/effect readback, and complete native finality remain unproven.

Original business throughput, effective independent useful-task throughput, full model-weight delivery throughput and actual model-service throughput remain **unqualified**, not zero-valued measured capacity. WAN, churn, cold recovery, real demand and production qualification still open.

## Reproduction and preservation

For these exact artifact downloads only, `sha256sum <zip>`; `unzip -t <zip>`; inspect `source.json`, `history-native/history.log`, `history-native/long-history/summary.json`, `history-native-host/controller-result.json`, `history-native/history-resources.txt` and compare `native-ancestry-public-server-exit-evidence-v1` with `native-ancestry-independent-sync-exit-evidence-v1` records. For the original campaign also stream each `artifact-files.json` entry into a SHA-256 check (1,765 records). Never add nested calling-thread CPU time to enclosing import CPU time.

**Admission: Draft / HOLD_NO_GO.** This document is exact-source observation and does not establish any production claim or provide new authorization to merge.
