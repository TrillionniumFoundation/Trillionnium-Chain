# R1 local Host diagnostic entry — final read-only review

## Decision

The original native Python CLI can be called without pretending to be GitHub Actions. **It is not presently a faithful local substitute for the required four-second confirmation gate.** The loopback listener exception does not extend to public History import: the exact importer used by the confirmation fixture explicitly requires the fixed administrator-owned parent, even when its source socket is loopback. The available Hepta process API cannot establish that complete contract. Do not start native work merely to collect the predictable environment refusal. The current required validation gap remains for the unchanged hosted gates.

Scope is immutable R1 commit **2a86462a1ab20c68151719ba4635e3c294391e64**, tree **5c26776f96f15fd131e85a5c2d7c5e895ad7fab4**. No native execution, benchmark, Host controller, process resource request, source edit, ref edit, stage write or network request occurred. All commands in this review read immutable Git objects or already retained evidence and write only this external review directory.

## Exact entry and the missing precondition

The actual CLI is:

    python3 scripts/ci/run_from_zero_native.py --out <new absolute directory outside checkout>

Its only actions are --out and --summarize-confirmation; --observation-version is a read-only summary selector. There is no build-only, execute-only, prebuilt-binary, skip-Host or local-quota override.

The fixture binds its TCP listener to 127.0.0.1:0. The library's require_for_listener returns None for this development listener, as documented by host_kernel_parent.rs:1573–1582. **That fact alone was an incomplete basis for local replay feasibility.** The same fixture then calls receive_public_page_from_before_observed at public_v3_from_zero.rs:1452. Its implementation at ingress.rs:2681–2711 deliberately supplies Some(FIXED_PUBLIC_KERNEL_PARENT), observes Resolve and Initial, checks the actual kernel at every original checkpoint and performs the final observation. Socket address cannot waive public History provenance.

The kernel owner requires canonical /sys/fs/cgroup/trnmponpublic.slice, root ownership, unchanged boot/device/inode, actual calling-thread membership, all five finite limits and fresh complete reads. It opens the current parent on every check, opens regular children with NOFOLLOW/NONBLOCK, reads through EOF, and fences path/ownership afterwards. Loopback cannot replace this importer with the weaker private development wrapper.

An existing, independently authorized real fixed parent could make the native CLI a local diagnostic, but no such current ROG condition was inspected or assumed here. Provisioning or migrating to that parent is outside this task, and even a matching local setup would not be the required hosted head/prospective result.

## Build preparation is not an execution bypass

run_from_zero_host.py has a deliberate two-stage pattern:

1. Outside the service quota, prepare_native_build performs the exact locked release target build with its original 900-second limit. It retains exact source and binary identities. The controller also runs the original 60-second formatting gate and retains the real preparation record.
2. After installing/validating the fixed unit, the original native runner executes inside the service and **still performs the exact 900-second source build**, selects the reported target, hashes and preserves the executable, and invokes all five exact selectors.
3. bind_prepared_execution joins the preparation and execution source/binary identities and requires all original acceptance stages. The narrow formatting receipt is checked against its actual source, versions, process and logs; it is not permission to invent a success or skip the build.

The five original selectors are caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct; from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection; four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged; from_zero_service_shares_cpu_with_honest_work_and_reopened_owner; and from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline.

The five selectors retain --exact --nocapture --test-threads=1 and 90 seconds each. A warm target can reduce build work; no original CLI accepts a supplied executable in place of its own verified build. Separate history/architecture preparation APIs do not replace this five-test runner.

## Budgets and state that must remain unchanged

| Contract | Original value or condition |
|---|---|
| Shared traffic deadline | One monotonic epoch + 4,000,000,000 ns |
| Pressure | 16 workers; up to 1,024 attempts per worker |
| Per-RPC deadline | min(original epoch + 4 s, call start + 2 s) |
| Work construction | 4,096 original trials; 16 original attack packets retained |
| Signed business | Same 7 packets in both phases; depth 6 and exact required work |
| Honest observation | 40 ms head polling sleep, 256 head cap; 64 submit cap; 16 History cap |
| Service lifetime | 30 s; it does not extend the 4 s business deadline |
| No late repair | No post-pressure replay, retry or drain can earn confirmation |
| Hosted kernel parent | cpu.max 25000 100000; burst 0; memory.max 2147483648; swap 0; pids.max 256 |
| Original process budgets | Format 60 s; build 900 s; each of five named native calls 90 s |
| Workflow orchestration | protocol 240 min; cross-arch cost 155 min; these are not business-budget changes |
| Build envelope | Rust 1.95.0; jobs 2; incremental 0; original serial native harness |
| Source | Exact head or separately checked prospective merge, verified before/after; executable SHA before/after |
| History ownership | Node-owned CPU domain and durable epoch; original reserve, settlement, close and abandonment fences |

The Host controller additionally checks its reviewed unit bytes, non-root uid/gid/cwd, NoNewPrivileges=1, empty capability bounding set, actual service membership and before/after context. It explicitly requires GITHUB_ACTIONS=true and CI=true and says never to provision a workstation. Neither setting those flags nor invoking its internal --inside path is an approved local substitute.

## Hepta resource API assessment

Only the declaration of h_process_start was read. It exposes cpu_quota_percent, memory_max_bytes, nice and timeout_seconds plus normal argv/cwd/env fields. It does not expose TasksMax, CPUQuotaPeriodSec, zero-burst/swap settings, slice selection or fixed-parent placement.

The requested 25% CPU and 2 GiB can therefore be expressed in isolation. The schema does not prove the exact 100 ms period, zero burst/swap, 256-task ceiling, original parent path or current-thread membership. Its undocumented defaults were not assumed. An owned alternate transient group with similar numbers remains a different Host, and the original public importer would reject absent/wrong parent identity. No start call was made.

## What the already closed N failures support

The evidence below belongs to old N, not R1. Both original protocol executions passed all five Rust invocations and service/sustained validators, then failed the confirmation validator with CONFIRMATION_TARGET. The Rust confirmation test intentionally asserts safety/accounting invariants and retains finite-business outcome separately: Cargo exit zero is not confirmation acceptance.

| Original artifact | Baseline final confirmation | Pressure submissions | Pressure History/replays accepted | Failing replay |
|---|---:|---:|---:|---|
| 14111407094 (head) | 3.191665508 s, 1 confirmed | 7/7; last ACK 1.694434484 s | 1/1 History; 0/1 replay | 1.793263152 → 4.090965490 s; 89.051928 ms caller CPU |
| 14111816359 (prospective) | 2.877335016 s, 1 confirmed | 7/7; last ACK 1.566020707 s | 2/2 History; 1/2 replay | Second replay 3.465184758 → 4.061195689 s; 36.714448 ms caller CPU |

The first prospective replay consumed 1.701114815 s and succeeded. Both final failures were PUBLIC_REQUEST_DEADLINE. This localizes the lost confirmation to independent replay after the successful signed submissions; it does not prove a particular scheduler or storage cause.

The retained native attribution gives concrete, separate costs. Head replay recorded 28 page-reserve attempts, 27 budget refusals and 27 sleeps: 54 ms requested sleep versus 333.718592 ms observed sleep wall. Prospective first replay recorded 9 attempts, 8 refusals/sleeps: 16 ms requested versus 398.327679 ms observed. Original fresh Host checkpoint calls were 1,188, 1,174 and 594 across the three pressure replay rows; all of those Host checks accepted.

These counters are not policy.id invocation counts or the old C0 trace's coincident 1,099 Host count. Host wall sums can overlap; Host CPU includes every invoking thread while outer phase CPU can exclude scoped workers. They cannot be summed or used as exclusive percentages. Wall minus caller CPU alone does not prove CFS throttling. Owner::Exclusive in this fixture uses &mut Node, not the shared Node mutex retry loop.

## Next diagnostic decision

Wait for the original R1 hosted head and prospective gates. If they fail, first read their already-existing per-page replay, Host checkpoint, CPU wait, durable epoch and final confirmation records, along with the original controller context and all raw logs. Preserve failed and missing denominators and compare baseline versus pressure under the same source.

Only propose a code change after an identifiable redundant pure computation or allocation is demonstrated. R1 already has the reviewed immutable public-policy prefix cache; there is no measured four-second benefit yet. This review selects no nonce change, dynamic Host cache, skipped callback, altered accounting, new deadline, reduced worker count or changed pressure cadence.

## Corrections and retained failure

An earlier listener-only note suggested an unprovisioned loopback performance run. Complete traversal of the public History importer disproved that inference, and root was notified immediately. The final conclusion above supersedes it while the preliminary note is explicitly retained in review.json.

One read-only extraction attempted a separately extracted confirmation/report.json path and returned FileNotFoundError. The full reports were retained inside the already verified ZIPs instead; they were subsequently read from the exact existing members, with original report SHA256 values checked. The failed extraction script and its complete terminal remain in this evidence package. No native run or network retry occurred.

## Primary evidence

- source-index.json and entry-excerpts-v1/source-index.json bind the immutable commit, fixture, workflow, unit and captures.
- The existing source-comparison summary, SHA256 763be7d2f5c5dfe41889e181e767db9f81dc0d822964dd248f8642dad73667a3, establishes original runner/fixture equality across N/N2/R1.
- final-entry-and-timing-excerpts-v1/ingress-resource-entry.txt contains the public importer guard; kernel-host-contract-v1 contains the exact current kernel owner.
- bounded-N-phase-timing-v1.json binds raw report hashes 6ca59b1b4d4b0af4f3cd615a9ec1860e722fc1721bf5a36e8e071ae80e455748 and 1814ade47a1c616c96cdb95b5e510ff3ec07c922a43549f53a6f6e26ec4de68f.
- tool-process-start-declaration.txt preserves the actual read-only API declaration.
- readonly-capture-provenance/ contains all eight inspection programs and their complete original PTY terminals, including the one extraction failure.
