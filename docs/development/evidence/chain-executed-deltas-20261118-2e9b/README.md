# Reuse actual native execution deltas for authenticated persistence

## Problem and bounded change

The original F0 at source `7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8`, run [44315121617](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44315121617), failed with 1/6 confirmations inside the original thirty-second phases and 0/6 against the scheduled four-second target. Full original bytes and independent readback remain in Draft #958 and the adjacent `chain-fixed-root-f0-20261118-2e9b` evidence.

The baseline client's 12 History imports made 121,963 Host checkpoints. The exclusive commit attribution was 62,107 calls / 2,636,001,313 ns of nested Host CPU. Actual stored full snapshots for heights 5–15 contain 11,473 union-key visits but only 26 canonical delta rows. `original-profile.json` independently recomputes those counts from the retained original SQLite snapshots and records the wider stage costs without adding nested intervals.

This candidate uses the complete canonical changes already produced by the original owner's real M06 execution to write authenticated-v1 deltas. Both held-owner and opaque detached-owner execution construct this optional write material internally. Each actual delta write retains its Host/CPU/cancellation checkpoint. The candidate does not accept public StagedOutput or caller-supplied changed-key lists.

Only authenticated-v1 with no task manifest uses this path; Legacy, PQ, Growth and all task-output re-derivation paths retain the existing full union. Public PreparedCommitment is not authority. The existing authenticated publish independently re-reads the actual SQL deltas and completely canonicalizes both actual States through matches_difference. Missing, extra or incorrect material therefore fails before commit. Original snapshot, packet, complete State, ancestry, active-tip, schema, transaction-owner and final callback fences remain in place. No original validator or guard assertion changed.

This removes one repeated full-State delta-candidate enumeration. The original account-graph traversals remain: baseline client account_graph was 84 calls / 4,365,213,739 ns of nested CPU, with 117 verify_state calls. Neither the eliminated-key count nor the native controls establish the business deadline. All costs remain charged by the original accounting.

## Native validation and retained failure

Rust 1.95.0 release jobs on ai395:

| Selector | Actual result |
| --- | --- |
| New executed-delta negative/parity/rollback controls | 3 passed |
| Original detached admission selector, including those 3 controls | 23 passed, 1 explicitly ignored |
| Original authenticated selector | 123 passed, 1 explicitly ignored |
| Original legacy admission selector | 8 passed |
| Original task_output_root_parity integration test | 2 passed |
| Original pon_commitment selector | 15 passed, 2 explicitly ignored |
| Strict trnm-pon-node library Clippy | passed, -D warnings |

The new controls compare all actual SQL tables and cold reopen between the native-delta path, literal full-union fallback and held owner; inject missing, extra, wrong-before, wrong-after, reversed and non-UTF8 material; and cancel at every actual delta row and the final commit boundary. They establish refusal/rollback and state parity, not service throughput.

First job `1a1ef2f794c-ffbe-425` passed the node and task-output controls, then the original commitment crate's test compilation failed because the sparse checkout omitted `tests/vectors/pon/native-growth-reference-v2.json`. The original failure is retained. Retry `1a1ef350e7f-ffbe-434` materialized that exact HEAD Git blob, verified all previously hashed files unchanged, and passed the remaining original commitment controls and Clippy. No assertion was weakened or test result replaced.

`native-originals.tar.xz`: 162,556 bytes, SHA256 `5e4f4f284b21d44522f824965959473f9f78dc1de068e3b41098f65e0c4e269c`. It retains both attempts, complete stdout/stderr/exit files, the actual formatted patch, source files, 1,705 source/vector hashes before/after and actual native test ELF identities. Full test ELF bytes are explicitly not in this archive. Local independent readback verified the archive hash, every before/after hash and the three tested source bytes against the published candidate inputs.

Project preflight, all 2,617 current source blob correspondences and the original native ownership omission/mutation negative control passed. Only the three new current source blob pins are refreshed relative to #959; historical evidence and qualification assertions remain frozen.

## Business and cost status

This is a separately frozen candidate stacked on #959. The original F0 workflow is to run on its exact published source, with all six scheduled confirmation targets, 42 exposures, 24 ROOT attackers, scalar CPU and memory bounds, original readers and failed/unobserved denominators unchanged. The #959 run 44328450170 is preserved independently; its result must not be transferred to this source.

Complete physical cost remains UNKNOWN: these archives do not measure system-wide energy, provider charges, all concurrent physical memory, physical network traffic or storage byte-seconds. Native/accounting/OS counters retain their original scopes and failures; nested CPU is not added. No independent-operator, WAN, production activation, consensus-hardness, FinalUse or reward-settlement qualification is claimed.

Prior #959 F0 has now completed with 0/6 original-window and 0/6 four-second confirmations. Its full provider ZIP and source-pinned independent failure readback are retained in the adjacent Host evidence, with the exact prior source attribution. This negative does not qualify this new candidate.

## Frozen-candidate original F0: still failed

The original campaign ran exactly once on source `e6af21fd47347ba900ef87842447ed6fe227a6f0`, tree `af911ad472b7820f8c6c7d4c9a425097263d80ac`: [run 44335832525](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44335832525), job 134912190949, artifact 14444536755. The six scheduled four-second targets all failed. In the original thirty-second windows, baseline completed 2/3 rounds and ROOT completed 0/3: **2/6 original-window confirmations; 0/6 four-second confirmations**.

Baseline round 0 completed 13.491849234 seconds after its scheduled start and round 1 completed 22.895946839 seconds after its scheduled start. The baseline third round and all ROOT rounds remained unconfirmed. The fixed 42 business exposures retain 28 timely ACKs (baseline 21, ROOT 7), 14 unattempted exposures and no further attempted exposure without a timely ACK. ACKs do not establish confirmation.

The actual native selector exited 101. The original readers still refuse with `BASELINE_MUST_PASS` and `F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED`. The same workload, 24 ROOT actors, 0.25 CPU / 2 GiB public Host, one M06 worker, original schedules and deadlines remained. All seven original native preparation controls passed. The six controller-resource boundaries, actor identity/reaping and empty exact-owned services were checked. Successful cleanup does not change the business failure.

### Actual cost and remaining work

| Observed scope | Baseline | ROOT |
|---|---:|---:|
| Actual client History imports, including failed import | 15 | 6 |
| History caller thread CPU | 5,081,848,029 ns | 1,653,096,815 ns |
| Host checkpoint calls inside those imports | 152,248 | 43,587 |
| Nested Host checkpoint CPU | 3,775,608,403 ns | 1,283,133,773 ns |
| Whole original public phase process CPU | 8,303,816,826 ns | 8,660,550,413 ns |

The baseline Host checkpoint accumulator partitions into commit 64,433 calls / 1,600,746,465 ns, submit_result 42,592 / 1,057,170,882 ns, admission_prepare 29,143 / 720,634,122 ns, work 15,441 / 378,821,187 ns, and the remaining explicitly retained buckets. No clock-unknown or unfinished checkpoint calls were observed. Account-graph stage observations on the client still contain 124 calls / 3,792,781,766 ns in baseline and 28 / 1,235,268,528 ns in ROOT. These graph/admission/publish costs nest and must not be added to one another or to Host CPU.

`cost-profile.py` reads the three immutable original ZIPs, the actual History packet identities/phase costs, application byte counters, final CPU-credit flow and final SQL account roots/deltas. It also counts the concrete no-account-change publication opportunity from retained databases. Such counts are potential removable work, not observed saved work or acceptance. Every attempted, failed and missing business result remains in the original archive.

The prior frozen runs remain failures: run 44315121617 was 1/6 in original windows and 0/6 at four seconds; #959 run 44328450170 was 0/6 and 0/6. These ran on different GitHub runner allocations and completed different amounts of work. Their raw CPU totals or observed confirmation counts do not isolate a causal speedup from either patch. This candidate does not close F0.

### Retained originals and independent reader

- `f0-original.zip`: 19,573,624 bytes; SHA256 `6ab6d65c68a2d0b36e49995507dbcc7f7728e16fec3fe6e20de53cb1fdff62fa`, equal to the GitHub artifact digest.
- Actual raw report SHA256: `3f743d1327dc25f6cb9ece8908518fa7d02bd84feaf6ff831169e5b8f490c5cb`.
- Retained native ELF: 13,138,696 bytes; SHA256 `9ab52eb79508e86cd7ab5965aaa4823a35869284e7c6ddb6eff97a01b30ea6f9`.
- `f0-readback.py` pins all twelve original reader source blobs. It verifies every one of the 443 manifest members, exact source/tree before and after, preparation, actual ELF, original business refusals, all six rounds / 42 exposures, controller observations and cleanup. Its output is `f0-independent-readback.json`.
- `cost-profile.json` is the reproducible measured-scope comparison, not a substitute gate.

Full physical cost is still **UNKNOWN**: compiler/dependency CPU, concurrent whole-system RSS, physical network/storage I/O, storage byte-seconds, GPU activity, energy and provider charges are not manufactured from application bytes, nested clocks, snapshot RSS or software retention charges. No production activation, independent WAN, multi-receiver or Sybil qualification is claimed.

The first auxiliary summary write encountered a null-key JSON sorting error after validating the unchanged original ZIP. That analysis-only attempt is retained as job 1a1ef67916c-ffbe-4c1; job 1a1ef68709b-ffbe-4c6 corrected the output label and reread the same archive. The native workload was not repeated.
