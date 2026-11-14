# C0 W1 scheduling and classical authentication: bounded read-only causal review

## Outcome and authority

No performance repair is established by this review. The two C0 cross-cost confirmation failures remain failures of the original confirmation target. This work neither executes a test nor changes production source, source mappings, Git objects/refs, the workload, the 4-second deadline, the 16 pressure callers, the 0.25-CPU Host contract, or any qualification flag. It does not claim hosted acceptance or a complete semantic audit of the repository.

The fixed source checkpoint is `1a7afcdb820b051d1e4bfde3d436f96fc050c487`, tree `18c3d20df915f5c31ee38c7037775c61e5c12e3f`. The actual C0 artifact producer is `dc42ce4df5cff79cc61c5addbaf01074b56b06ca`, tree `9fda17fed2542b2baccaa34585bb00afd699e12b`. Each selected runtime source exported for this review has the same Git blob at both checkpoints; the machine-readable selected source manifest supplies the full paths, blob IDs, byte sizes and SHA256 values. A whole-tree Rust/Cargo name comparison found four added evidence-carrier `.rs` files, so it would be incorrect to describe that name comparison as an empty diff.

This is a source-backed explanation of the observed route and its accounting boundaries. It is not a scheduler trace, a per-syscall latency measurement, a proof that all off-CPU time has one cause, or an assertion that the rejected original confirmation target is infeasible.

## Evidence and original observation scopes

The authoritative input reports are:

- x64: `critical-members-v3/x64/members/from-zero-native/confirmation/report.json`, 12,119,117 bytes, SHA256 `1feec4c23449c6f9741fb40fb70637a4198495e98303605c7b47d3ce832d5ab0`.
- arm64: the corresponding arm64 path, 16,002,976 bytes, SHA256 `99f3b7bb894ff4bc8a9d18a94aa608e093171e69b8ab2798f4a263bcc3e40333`.

Both live below `/private/tmp/chain-c0-cross-cost-diagnosis-20261114-v1/`. The artifact owner independently closed each entire ZIP against the API SHA and all 161 members. This review consumes the verified original reports and bounded extracts; it does not claim to have redownloaded or independently revalidated every ZIP member.

The pressure service subset is `pressure-charge-review-v1/pressure-charge-summary.json`, exact JSON pointer `/phases/1`. The replay extraction is the peer's `hotpath-readonly-v2/all-replay-phases-and-waits.json` (SHA256 `920783335d16d47ee2c2ce469ea74afea0500ff0692c512b7d5a81b69e86db5c`). The source and archive indexes bind these references.

| Actual observation | x64 pressure | arm64 pressure |
| --- | ---: | ---: |
| History replay records / accepted | 1 / 0 | 5 / 4 |
| Decisive W1 interval | 1,796.920567 ms wall; 82.609255 ms calling-thread CPU | fifth record: 198.122240 ms wall; 9.692928 ms calling-thread CPU |
| Fresh Host observations in that W1 interval | 1,099, zero Host rejection | 337, zero Host rejection |
| Host CPU nested in that W1 interval | 78.779013 ms | 9.204048 ms |
| Host wall intervals, summed inside W1 | 379.990588 ms | 105.300086 ms |
| Actual terminal boundary | W1 completed, later original deadline boundary rejected | original deadline rejected before W1 completed |

The first four accepted arm64 pressure replays each retained all 1,099 Host observations. The fifth does not provide a completed-proof sample. The x64 page first incurred 56 reservation attempts / 55 budget refusals: 110 ms requested sleep became 300.844881 ms elapsed sleep, within a roughly 304.826 ms CPU-reservation wait. That wait occurs before W1 and must not be relabeled as a wait inside the arithmetic verifier. The 95.6 ms durable epoch begin is a separate page boundary.

The x64 W1 wall-minus-thread-CPU difference is approximately 1.7143 seconds. It does not identify that time as lock contention, a particular kernel throttle interval, sleep, or worker CPU. Subtracting its nested Host CPU leaves approximately 3.830242 ms, but that residual is not a clean arithmetic-only benchmark: interval boundaries and observation overhead differ.

## 1. Actual W1 path and the 1,099 observations

The route is synchronous:

`receive_public_page_from_before_observed` → exclusive History owner → `metered_observed` → `verify_history_work` → `WorkCheckedPacket::verify_with_progress` → `pon_work::verify_with_progress` → FullLimb loops.

The source anchors are Node `ingress/history_import.rs` 32–38, 58–83, 194–270, 310–338 and 353–394; `store.rs` 1200–1221; crypto `pon_work.rs` 481 onward, 709–774, 824–906, 1017–1137 and 1229–1260; and `pon_work/maintenance_limb.rs` 18–62. There is no nested worker pool, numerical permit wait, sleep or yield in the selected FullLimb arithmetic bodies. M06 execution/worker attribution begins after W1 and cannot explain this W1 calling-thread CPU gap as an unrecorded W1 worker pool.

For the concrete complete proofs in these reports, the callback count is consistent with:

`3 boundary checks + 256 noise expansion checks + 128 preparation-row checks + 512 tile checks + 200 correction-row checks = 1,099`.

This describes the observed packet and actual control placement, not a universal constant for every proof: rejection sampling can cause additional noise-expansion iterations. No removal, batching, sampling, or reuse of these fresh checks is proposed.

Each History progress callback preserves alive/deadline checks around the scalar/Host boundary. The already-present adjacent duplicate Host observation removal at `history_import.rs` 318–322 has been retained; proposing that optimization again would misdescribe the current source.

## 2. Scalar locks, waits and actual ownership

The two scalar mutexes are the request's live account and the service/domain budget. `scalar_cpu.rs::observe_sample` (787–880) takes the request lock before the budget lock, computes checked actual CPU/refill/debit, and performs no Host reads, W1 arithmetic, SQLite transaction, worker join or deliberate sleep under those locks.

The 5 ms verified-completion wait in `observe_with_control` (678–710) is gated by verified native completion in `observe_sample`; `mark_native_complete` is later. W1 has not reached that state. The shared History owner's 1 ms Node-lock retry (History owner lines 73–83) is also inapplicable: the reported replay uses `Owner::Exclusive`.

The fixture creates two different Nodes: an independent client/verifier Node and a receiver Node (`tests/public_v3_from_zero.rs` 1285–1305). Only the receiver is wrapped for the public service. Replay uses `&mut verifier` at 1452–1461. Thus the pressure workers do not hold the same scalar account/Node mutexes as this exclusive W1 replay. They still compete within the same imposed Host resource envelope. Source inspection rules out those particular shared-owner explanations; it does not measure arbitrary kernel scheduling delays.

## 3. Fresh Host cost is real; the obvious changes are already present

`host_kernel_parent.rs::checked_parent` / `open_current_parent` and the scoped child-read path revalidate current boot/member identity, freshly open the parent with the required no-follow flags, read and verify the five original limits, check regular-file/EOF behavior, and fence parent identity again. The held parent descriptor is scoped to one current check.

Current implementation already includes fresh `openat` child reads, constant child-name C strings, stack buffers for ordinary bounded data, iterator-based limit parsing, and the same-stream longer-input fallback. A short read cannot replace the explicit EOF check. Reusing a prior success, skipping one limit, caching a cross-check parent descriptor/verdict, or reducing callback frequency would weaken the selected contract and is excluded.

The measured 78.779013 ms x64 Host thread CPU is nested within the measured 82.609255 ms W1 thread CPU. It is evidence of cost, not evidence that a particular current read is redundant. No safe omitted dynamic validation was found, and no syscall-level latency/count measurement was performed.

## 4. Pressure admission and rejection CPU

The receiver's initial 2,000,000,000 ns scalar credit, 250,000,000 ns/second refill, 100,000,000 ns start reservation and two mutation workers match the explicit warm policy. This ledger policy does not promise two seconds of physical CPU inside a four-second 0.25-CPU window.

| Receiver pressure accounting | x64 | arm64 |
| --- | ---: | ---: |
| Accepted connections | 371 | 525 |
| Charged mutation CPU | 319,578,028 ns | 262,513,896 ns |
| Full-work subset | 104,809,767 ns | 81,818,672 ns |
| Dispatch excluding full-work subset | 214,768,261 ns | 180,695,224 ns |
| CPU reservations / refusals | 331 / 0 | 470 / 0 |
| Clock failures / final in-flight / debt | 0 / 0 / 0 | 0 / 0 / 0 |
| Final stored credit | 1,999,428,177 ns | 1,999,784,190 ns |

Body-decode and response-signing measurements are nested within these charged intervals. They must not be added again. Summed per-request queue-wait wall durations overlap and are not phase elapsed time.

The actual service starts two mutation workers and one read worker with bounded FIFO queues. Its original CPU reservation loop preserves deadline checks and 1 ms retries without holding the Node lock during the wait. Actual failed work and unknown measurements do not acquire free refunds; settlement remains checked and conservative. The fixed r20 caller limits do not collapse this workload to two attackers: the original 16 workers rotate caller identities using `80 + ((attempt + worker * 37) % 150)`.

The bounded W1 rejection cache is already installed by service startup at `public_v3.rs` 2392; the constructor's initial `None` is not an inactive-cache bug. Current cache use retains authentication, current Node context, paid decoding, original deadlines and actual CPU debit. No cache activation or policy reduction is justified by this review.

Classic reactor challenge signing and caller verification remain outside that paid mutation interval. The observer explicitly reports `cpu_includes_reactor_authentication=false`. This is a known observation boundary, not a measured zero or permission to subtract those costs from the process.

## 5. Kernel evidence: actual throttling, broader scope

The independently read `additional-host-counter-originals-v1/aggregate-kernel-counter-deltas.json` (SHA256 `7f4ce5f87084b2f1b9a839b7895273d4d0df5bfd9b70abd275e3ba198744ee66`) contains:

| Entire original child command | x64 delta | arm64 delta |
| --- | ---: | ---: |
| cpu.stat usage_usec | 15,634,607 | 12,982,510 |
| nr_periods | 634 | 543 |
| nr_throttled | 622 | 469 |
| throttled_usec | 77,977,803 | 45,979,845 |

The producer source (`run_from_zero_host.py` 305–324, blob `df0643a36ab7110d0b5af9d13cd9e291bbf022f0`) captures before the original child command and in its finally block afterwards. The unchanged limit/identity records show 25,000/100,000 CPU, burst zero, 2 GiB memory, no swap and pids 256 with no read errors. These records establish actual throttling over that whole command. They do not align throttling to a particular W1 interval, isolate the four-second pressure phase, or support adding throttled microseconds to observed wall time.

The attacker-loop thread CPU totals (x64 354,481,431 ns; arm64 337,787,584 ns), receiver charged CPU, independent replay CPU, and reader CPU have different boundaries/tails. Their threads may be distinct, but their records do not supply one exact common four-second interval. A naive sum is not a proof that a particular deadline must fail. The whole-process wait4 CPU/context-switch totals include baseline, pressure and setup and likewise cannot be assigned to one W1 call.

## 6. Durable History epoch

The selected `store/operator_continuous_owner.rs` blob is `d94f27a764a2788e90352881b52fc9017a32ab67` (SHA256 `59398375101f36e234001dbd5bb15cd767a7b8537f457ccb104c41b110dfef4a`). `begin_remote` / `begin_ordinary` and completion maintain a durable active marker; with no live outer listener reference, an individual page has an INSERT boundary and the clean last completion has a DELETE boundary. Existing listeners share the same epoch reference and still validate the durable marker.

The current store already uses WAL and synchronous FULL. The reported begin interval may include the necessary write, but neither this review nor the existing phase record proves its fsync contribution. There is no existing production outer History session lease to reuse across pages in the reviewed callsites. Dropping persistence, changing synchronous behavior, or modifying only the benchmark to add a different lease is outside the selected contract. Root owns the parallel deeper epoch review; this report records no epoch source fix.

## 7. Classical identities: exact reuse and remaining repetition

`DevelopmentIdentity` holds an `OwnedEd25519Key` and a previously derived public string; signing uses the held signing key. The project code does not reconstruct its secret key or rederive its public string for every challenge/response. This statement does not audit or assert the absence of internal seed expansion inside the third-party signing implementation.

The classic client validates two distinct signed messages: the cookie challenge at `public_v3.rs` 3971–3973 and the response at 3892–3894. Both call the same immutable `ServerPin::Classical`, and both use the strict key/signature parser. Therefore strict public-key parsing is repeated within one call; the two signature verifications are necessary and must remain. A future lazy, same-instance parsed-key holder could reuse only the validated immutable public key while retaining both actual strict verifications, current-context checks and first-error ordering. Its benefit is unmeasured, and no such holder is implemented by this work.

The Cookie digest is also recomputed at several places within the same immutable Solution event. That bounded opportunity has not been measured and was explicitly deferred. The client's nonce loop already hoists the cookie ID outside the loop. None of these facts establishes a four-second repair.

The original pressure fixture constructs its configured server identity and its caller identity within its own call measurement. Those are two different identities and part of the original workload. The fixture, identity construction, identities, signatures and load remain unchanged.

## 8. Existing diagnostic entrypoints

The fixed-revision search and complete relevant definitions are indexed in `existing-diagnostic-entrypoints-v1/` and `existing-entrypoints-review.json`.

| Existing entrypoint | Actual scope | Can it measure classic server reactor sign/verify CPU as-is? |
| --- | --- | --- |
| `PublicRequestObserver::new` | V4 local request/dispatch/I/O/phase observations | No; explicit reactor-authentication CPU flag is false |
| `new_with_authenticated_callers` | V5 adds authenticated caller identity | No; the same false CPU coverage flag remains |
| `ReactorIoStamp` | Calling-thread CPU around actual read/write wrapper returns | No; crypto is outside those wrapper intervals |
| `call_public_protected_v3_with_cpu_observation` | Whole client-thread call and nonce-search observation | No; it explicitly says server CPU is unknown |
| PQ `AuthenticationBudget::perform` | Actual PQ authentication reservation/debit/refusal | No; it is an authoritative PQ budget, not a classic diagnostic switch |

Current phase/report consumers require the old false reactor coverage flag; relabeling V4/V5 as covering that CPU would be false and would break those strict contracts. There is no selected existing switch that fills this classic server CPU interval without new engineering. The companion design is explicitly proposed, not implemented or executed.

## 9. Proposed next engineering work and unresolved acceptance

The smallest justified next engineering step is two opt-in, bounded, calling-thread observation intervals around the actual classic challenge-sign and caller-verify calls, with a separate sidecar schema. It must preserve original return values, ordering, deadlines, all Host/progress checks, paid accounting and V4/V5 bytes. Diagnostic failures stay unknown and cannot grant/refund/complete work. Measurement overhead can perturb scheduling, so even a semantically observation-only implementation is not a claim of zero timing effect or identical deadline outcomes.

Only after that implementation is separately reviewed and its original controls retained could the exact permitted hosted diagnostic expose the unmeasured classical-auth cost. No native or hosted execution is performed or newly authorized by this report. Existing acceptance still requires the unchanged original confirmation target; an additional diagnostic is not a substitute.

The present evidence excludes several specific false explanations and identifies a real measurement gap. It does not justify a source optimization claim, a changed resource policy, a relaxed deadline, or a changed workload. Cookie reuse, same-call parsed-key reuse, and any longer-lived History epoch API remain unimplemented and unqualified.

## Read-only inspection exceptions

Earlier bounded source-export/read scripts encountered (1) a mistaken zero Rust/Cargo delta assertion, (2) a guessed maintenance-limb path, (3) a grep parser that retained a line number in a Git path, and (4) a guessed telemetry field name. Each ended and was recovered by exact source/schema inspection. A later two-file view used the short crate name instead of `trnm-crypto-primitives`; both were read from the indexed correct paths afterwards. These are preserved tool/query errors, not native test failures. No successful test was rerun, no source was changed, and no failure was replaced with a claimed pass.

## Immutable source permalinks

These links identify C0 bytes; the selected source manifest proves equality to the reviewed checkpoint.

- [History progress and owner](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs#L310)
- [W1 FullLimb verifier](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs#L824)
- [Scalar observation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs#L678)
- [Fresh Host verification](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L550)
- [Classical authentication branch](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs#L249)
- [V4/V5 coverage declaration](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs#L898)
- [Actual independent verifier fixture](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1285)
- [Durable epoch owner](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs#L300)
- [Strict public-key/verify parser](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/trillionnium/crates/trnm-crypto-primitives/src/lib.rs#L102)
