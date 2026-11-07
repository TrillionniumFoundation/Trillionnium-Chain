## Problem and resulting behavior

A forged caller claim must not spend another account's authorization. A native commit must remain authoritative when authentication saturation, cancellation, signing or transport later prevents a signed ACK.

This PR integrates the reviewed authentication boundary and the R17 response-signing reservation. After an authenticated complete request is dequeued, the worker reserves response-signing principal and a slot **before decode and native dispatch**. Actual signing consumes that reservation once; actual owner settlement or retirement controls release. Pending, unknown and unwinding owners retain their accounting obligations. Attempts and input bytes are not refunded, and no additional CPU allowance or signing retry is created.

The reservation partitions the original budget. It does not guarantee ACK delivery after a deadline, network failure or an actual PQ lifetime overrun. Native commit facts remain available for reconciliation. Busy, timeout and unknown remain service outcomes, not consensus invalidity.

## Published candidate and concurrent changes

- Head: `40194538c7d74d860f9f0460d9f5f886df13281c`
- Tree: `977db7f413da494051d84ed3eecd1eb0522dfd12`
- Reviewed live target: `fix/chain-six-axis-performance-20261103` at `04bbc81e4aad9b29fef29385d3262297e2cb17df`
- Normal merge parents: `2f66491d06453d9b5c9a1783f9441fb1d07619a3` and the target above.

The candidate preserves the concurrent bounded exact mathematical-refusal cache, same-writer Legacy readback, Cell-consumer continuations, original failure evidence and existing integration source resolver. All tracked paths outside docs/evidence are byte-identical to the tested 2f candidate; all 173 unchanged upstream specification/evidence blobs were compared with 04bbc81 and preserved.

The repairs after f97 affect retained test fixtures, one Legacy test owner scope, required source pins and the development plan. Production behavior after f97 is unchanged. Queue tests authenticate their original grants, observe two actual workers and two occupied channel slots, then send the remaining pending bodies. All original deadlines, queue/worker limits and cancellation assertions remain. The complete 436 module's 843 assertion calls, 21 wait calls and 174 Duration expressions were preserved.

## Exact-head completed component validation

| Check at 40194538 | Result |
| --- | --- |
| Complete retained Public V3 selector | 249 passed, 0 failed, 1 existing ignored benchmark; 250 listed |
| Legacy readback controls | 7 passed, 0 failed, 0 ignored |
| Workspace/all-target/all-feature Clippy, `-D warnings` | Passed |
| Five original CI/source/PQ/policy/readback control suites | Passed |
| Locked default / all-feature / fuzz Cargo graphs | Passed; 175 / 180 / 147 packages |
| Source and lockfile identity after execution | Unchanged |

The existing `pq_caller_authentication_complete_cost` benchmark still requires a fresh output directory and remains ignored. Compilation and Clippy reused the valid native cache for byte-identical code; the selector tests actually executed. These component results do not assert that the entire workspace runtime suite or original fixed-Host qualification passed.

[Exact-head native results](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/validation/native-final-composition/summary.json), [original-case readback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/validation/native-final-composition/original-case-readback.json), [source controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/validation/source-final-composition/summary.json), and [locked graphs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/validation/graphs-final-composition/summary.json).

## Original resource gates: HOLD / NO-GO

The following are actual retained **f97** observations, with prospective-merge lanes at **6cd7b65** and shared tree **fb08f394**. They are not assigned to the newly started 401 CI.

| Original gate | Retained result |
| --- | --- |
| 0.25 CPU, 2 GiB, zero swap, 256 PID, zero burst; 4 seconds / 16 hostile | Actual GitHub fixed-Host head and merge samples ran with verified original limits. Both pressure samples confirmed 0/1 required targets; both baselines confirmed 1/1. Both pressure samples acknowledged all seven honest Submit requests. |
| Three complete 0/24/24 campaigns | All three processes executed all phases and returned 101. Of 27 planned confirmations: 3 timely, 9 observed but not timely confirmed, 15 unobserved. Baseline 3/9; both hostile phase types 0/9. All nine phase criteria failed. |
| Full 4,105-block History, x64/ARM head/merge | All four lanes executed and failed. Successful import returns were 4,028 / 2,792 / 4,104 / 4,104. x64 reached the original 1,800-second server lifetime; ARM's final import reached the original approximately 30-second request deadline. These returns do not establish durable activation, full cold reopening or corrupt-index refusal. |
| Native State full capacity, refund and pending reorganization recovery | All four original retained lanes passed. This is a release-profile native test, not the original public Host wrapper or PN1 identity-capacity/churn qualification. |
| PN1 identity capacity/churn | Not qualified; requires its own original finite workload and genuine occupancy/depletion/recovery evidence. |
| Independent WAN | Not qualified; hosted CI and same-host processes do not establish independent operators and failure domains. |

The campaigns observed 84/84 honest Submit ACKs, while confirmation completion remained 3/27. Finite p95/p99/max for all offered confirmation tasks are unavailable. All 3,967 retained budget samples reported no depletion; all 520 projected-start-ineligible samples had two live owners. These observations do not establish the original paid-depletion criterion or continuous-time absence of depletion. Distinct meter/flow/freshness reads are not treated as one atomic snapshot.

The historical local original-Host readiness refusal is preserved alongside the later actual GitHub executions. No Host limit, deadline, campaign denominator or History workload was relaxed. Source/component passes do not change these failures.

## New CI snapshot

Readback window: 2026-11-07T18:50:56.063311+00:00 to 2026-11-07T18:51:11.564638+00:00. Source: `40194538c7d74d860f9f0460d9f5f886df13281c`.

Workflow states: 2 failure, 7 in_progress, 7 success (16 total). Job states: 9 failure, 27 in_progress, 3 skipped, 66 success.

The workflow and job endpoints were read over this interval, not as one atomic scheduler snapshot. No new original-resource qualification is granted by this readback.

Observed unsuccessful completed jobs:

- [PoN W1 work security observations — W1 fresh challenge service (x64, head)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831771/job/128491082501): failure.
- [PoN W1 work security observations — W1 fresh challenge service (x64, prospective-merge)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831771/job/128491082569): failure.
- [PoN priority acceptance — retained-pressure-failure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831787/job/128491081956): failure.
- [PoN fixed Host ROOT F0 diagnostic — F0 (x64, head, one baseline and one ROOT phase)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831712/job/128491081662): failure.
- [trnm-required-baseline — cross-arch-cost (x64)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831625/job/128491081812): failure.
- [trnm-required-baseline — cross-arch-cost (arm64)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831625/job/128491081867): failure.
- [trnm-required-baseline — protocol-contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831625/job/128491081917): failure.
- [trnm-required-baseline — prospective-merge (protocol-contract)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831625/job/128491082363): failure.
- [PoN original native campaign — original native campaign (x64, head, release)](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401832002/job/128491082789): failure.

The new source-specific runs include [priority acceptance](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831787), [original campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401832002), [W1 observations](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831771), and [required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831625). Their results must be read from their own receipts.

## Immutable evidence and limits

[Complete report](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/README.md), [machine-readable qualification summary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/qualification-summary.json), and [file/encoding/digest manifest](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0d931bf0361d5e332d4216f88c8661c60aa7b88d/evidence/pon-w1-response-reservation-r17-final-20261107/files-manifest.json).

The separate evidence commit is `0d931bf0361d5e332d4216f88c8661c60aa7b88d`. It retains the complete original GitHub ZIP archives, raw failed observations, successful component controls, source/Host identities, all three independent audits and failed publication/readback drivers. The two earlier 246/3/1 fixture-repair observations and the f97 full node-library 1,201/4/31 result remain unchanged. Raw upstream whitespace diagnostics are preserved, and all 122 manifest-listed logs initially excluded by the generic ignore rule were explicitly staged without changing that rule.

A receiver-local Cookie does not prove anonymous fairness. Exact refusal reuse does not solve distinct false-trace asymmetry. This PR establishes no effective-work lower bound, single-node economic break-even, PQ cryptographic qualification or release/activation approval. It remains a draft while the original qualification gates are open.
