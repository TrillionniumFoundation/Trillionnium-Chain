# PoN open-consensus continuation — 2026-11-10

This package retains a reproduced journal-lease defect, its native repair, a versioned native-domain arithmetic oracle, and bounded History attribution. It also independently reads the original service failure. **Open-consensus and production qualification remain HOLD / NO-GO.** Component checks, source binding and publication do not close the remaining security or business obligations.

See [summary.json](summary.json), [raw-observations.tar.xz](raw-observations.tar.xz), [member-manifest.json](member-manifest.json), and the [original service readback](original-service-readback-summary.md). The manifest identifies retained raw files; individual command receipts bind source, command, environment, exit status and log digest. Observations below belong to their own source and execution scope.

## Source identity

| Role | Commit / tree |
| --- | --- |
| Integration base | `62378d28415ead28b5f99ec6ea6033fde93e3215` |
| Baseline with regression controls | `7cfa7602f0d9ff49902db5574773f602dea78020` / `73936d0dae27b998003953af1076c47f9eba7c6a` |
| First combined source | `ce4c5e7a6bc7e69805698b3e1131b425d093eceb` |
| Corrected source, published through [PR #876](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/876) | `0c589e2212f7feeaac4ec12d076d27ab139bc52f` / `831caac4edbae18921b3269a85faef456d78bbbe` |

The corrected source is a child of `ce4c5e7a`, which is a child of the integration base. The baseline retains the preceding production implementation with new regression controls; its failures are not substituted with successor results. Publication is not a main-branch merge, deployment or completed hosted validation.

## Three changes

### 1. Native journal lease ownership

The baseline accepted a live lock-name replacement, a directory replacement preserving the file inodes, and cold/live lock hard-link aliases. Five targeted controls produced **one pass and four failures** before repair. The two alias controls iterate over lock then journal; each baseline execution failed at the lock assertion, so its journal-alias subcase was not reached. The repaired suite exercises both names.

The repair retains the directory descriptor and lock descriptor, opens lock and journal relative to that directory with no-follow/nonblocking flags, and checks named-versus-held identity, owner, mode and regular-file link count. A detected live lease loss remains fenced even if the old names are restored. Checkpoint and native-operation entry cannot use that detected lost lease to append a successful receipt.

This does not detect an entire replace-and-restore between checks, authenticate hostile same-inode content changes, or establish independent custody. Trusted directory custody and separate external-effect reconciliation remain necessary. Journal formats and work rules are retained; these newly detected ownership losses now refuse.

### 2. Versioned native-domain reference

`native_consensus_reference_v1.py` models native nonzero-u256 targets, u64 time inputs, both checked u64 retarget products, upper-median recent ancestry and the wider future-clock addition. Current DAA readers use this reference to check decisions within the native input domains. The new 83-row vector set retains all 75 historical arithmetic rows and adds eight native-domain rejection rows; native test code consumes the versioned vectors.

The historical `reference.py`, `test_reference.py` and `consensus-arithmetic-v1.json` remain byte-identical to the frozen work-cost contract. No historical hashes were rewritten to make a changed model pass. This is an executable-domain consistency check, not a DAA, chainwork-security or work-cost theorem. Production consensus arithmetic is unchanged.

### 3. Bounded History attribution

An optional top-level `native_attribution` records domain lookup and durable epoch begin separately, owner mode, actual reserve attempts/returned outcomes, actual sleep counts/durations and remaining original deadline. Collection uses one page recorder and at most 16 indexed packet recorders, each with two fixed epoch-substep slots and two fixed wait slots.

Unentered capture is absent. Unknown clocks and checked duration overflow remain null. Capacity exhaustion or capture contention records measurement failure without granting credit or changing native work. Unwound actions keep incomplete outcomes. Sleep wall time includes scheduler overshoot and does not establish the cause of delay; nested intervals must not be added to their parents.

The original 19 phase entries, four Host row shapes and exact legacy packet fields remain unchanged. Existing readers tolerate the top-level extension but **do not validate its new fields**. Compatibility is not validation of the new diagnostic. Instrumentation adds overhead; no speedup or original-campaign improvement is claimed. Original budgets, cold-start semantics, fresh Host checks, deadlines and error precedence are preserved.

## Source-bound validation and retained failures

| Source / observation | Actual result and scope |
| --- | --- |
| `7cfa7602`, original journal implementation | Targeted native sidecar controls: **1 passed, 4 failed**. |
| `ce4c5e7a`, first native build | Compile failure **E0277**: two `rustix::io::Errno` results lacked conversion into the existing error type. No journal test success is inferred. |
| `ce4c5e7a`, Python controls | **478 passed, 1 skipped across 11 suites**; actual source/contract inspectors were recorded separately. |
| `0c589e22`, repaired journal integration suites | **27 passed, 4 top-level ignored helper entries** under the original test profile. Parent tests actually invoke the owned subprocess helpers; ignored entries are not counted as additional independent passes. |
| `0c589e22`, selected Python recheck | **326 passed across 5 suites**, plus separately executed inspectors. This overlaps the preceding Python controls and must not be summed into a unique-test count. |
| `0c589e22`, cloud monolithic node test builds | `rustc` terminated with **SIGKILL** under the original profile, node debug-info-zero retry, and node opt-level-zero/debug-info-zero retry. The selected consensus/History runtime tests did not execute in those attempts. |
| `0c589e22`, cloud strict all-feature workspace Clippy | **SIGKILL / exit 101**; no strict-Clippy pass. Metadata and formatting successes do not replace it. |
| Separate wrapper attempt | Missing `/usr/bin/time` caused **exit 127 before test execution**. This is a launch failure, not a native test result. |

`0c589e22` explicitly converts descriptor-open errors through `std::io::Error`; the earlier compile failure remains retained. Original/default and modified-profile build attempts remain separate. The SIGKILL observations alone do not prove a unique cause. Preparation errors and the interrupted cloud environment are retained as preparation observations, not fabricated native failures or passes.

Actual corrected-source CI-contract, corpus, current-QROM, selected-proof-profile, authority, native-inventory and repository-link inspectors were executed. Their successful consistency checks preserve their security-HOLD fields and do not certify deployed binaries or lifetime bounds. Native and fuzz locked dependency metadata and workspace formatting were checked separately.

## Desktop fallback: unresolved setup, no native qualification

Read-only observations confirmed Rust/Cargo 1.95.0 and about 81.8 GiB of available host memory at the recorded sample. An isolated default-profile verification checkout was prepared as a **request**, with its exact driver, source bundle, 12 GiB process ceiling and command roster retained. These observations do not establish an executed build or a reserved resource guarantee.

The authorized runtime then returned `-32603 Internal error` for binary transfer, file inspection, process launch and host health. The root session also received that error when reconciling the **identical original request and idempotency key**. No authoritative setup job ID or completed desktop native receipt was obtained. Setup effects remain **Unknown**; the error is not converted into a statement that nothing ran. No alternate setup operation was launched to bypass the unresolved request.

Consequently, the selected node consensus/History/Public V3 runtime suites and strict all-feature/all-target workspace Clippy remain **incomplete on the corrected source**. The successful original-profile journal integration result and Python checks do not replace those missing results. The source is a draft candidate, not a fully validated or production-qualified delivery. See the retained `desktop-blocker.json`, exact setup request and root reconciliation record in the archive.

## Original service campaign: independent readback, separate source

The original [run 42781760995](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42781760995) belongs to source `aaa3c53965bf0cf472e52451e205e9a020e834ab`, tree `fe3ce4c61bc2e3d477ea328b7742d0b2598282b3`. Artifact `13761459229` is 83,560,661 bytes with ZIP SHA-256 `715587a56f595588c4eca4b36ba6e0a326b78e69078a4240cc878959e1f02cfe`. Independent readback checked all 1,768 archive entries, the 1,767 exact manifest members, lengths, CRCs and SHA-256 values. No retained campaign binary was executed again.

| Original observation | Result |
| --- | --- |
| Complete campaign criteria | **0/3** |
| Complete phase criteria | **0/9** |
| Individual in-window confirmations | **6/27 planned rounds**; all six in baselines, zero under attack |
| Recorded / unreached confirmation rounds | **15 / 12** |
| Honest submission attempts / client successes / receiver full-work accepts | **90 / 87 / 89** |
| Exact-body hostile full-work rejections / accepts | **13,781 / 0** |
| Attacker processes launched and reaped | **144** |
| Genuine paid-credit depletion | **Not observed**; the required attack-phase condition also failed |

Two late client errors matched accepted receiver observations. Submit responses, full-work acceptance and independent confirmation are therefore kept separate. Six successful individual confirmations do not imply six accepted phases, and zero accepted campaigns does not mean zero individual confirmations.

The public Host's quarter-core and 2 GiB limits and the controller/attacker limits are ceilings, not reservations. Host cgroup CPU, process-phase CPU, setup and paid mutation CPU have nested scopes. Whole-phase intervals include setup and cleanup outside the 30-second business window; throttled duration is not consumed CPU. No whole-service amplification ratio or complete causal explanation is derived. The new diagnostic does not retroactively fill missing original observations.

## Four separate propositions and remaining obligations

| Proposition | Evidence still required |
| --- | --- |
| Real task demand | Independent authorization, actual demand and real resource/payment responsibility. |
| Correct calculation and delivery | Complete relation coverage and actual recipient verification/readback under the relevant service contract. |
| Net model benefit | Frozen independent future-task gains with all training, failed-attempt and adoption costs counted. |
| Consensus work cost | Bounds against the cheapest legal strategy, including zero/sparse/low-rank inputs, shared preparation, task selection, nonce reserves, hardware and multi-target amortization. |

The actual MU1 fixed-probability contract still retains **16 unknown classical/quantum cost points**, with `lower=null`, `upper=null` and unproved status. Finite vectors, benchmark timings and contract validation do not fill those bounds. The frozen historical cost inputs and previously failed observations remain preserved.

Open obligations include receiver-wide rejection responsibility across identities/restarts/hosts; original-window service liveness; joint DAA/timestamp/chainwork safety under network delay, hidden ancestry and mixed classical/quantum miners; CP/CG/CQ and confirmation-risk bounds; independent evaluation/demand governance; and target-side idempotency, durable journaling, reconciliation and `Unknown` outcomes for irreversible external actions. Correct relation verification, task demand, model benefit and work-cost security cannot substitute for one another. No model-quality, quantum-security, finality or production qualification is promoted by this package.

## Publication and reproduction boundary

The exact source commits were written through the repository-required ProfHepta local GitHub channel and independently read back at `0c589e2212f7feeaac4ec12d076d27ab139bc52f`. The publication helper checks object identities and the observed branch head, requests a nonforce fast-forward, then reads the result. This is not an atomic expected-head compare-and-swap. The integration PR remains a draft against the existing #847 candidate. Hosted workflow observations have their own identity and were queued/pending in the retained first-page readback; no hosted pass is claimed here.

The archive contains the test-only baseline bundle, corrected-source delta bundle, exact command receipts/logs, rejected unversioned-oracle attempt, independent original-service readback, and publication observations. The 83 MB original Actions ZIP and broad operator workspace/hardware inventories are excluded explicitly in the member manifest; original ZIP member verification and selected relevant environment facts are retained. Earlier raw files lost during the cloud reset are not reconstructed or represented as archived originals. The member manifest covers the actual included bytes, not omitted material.
