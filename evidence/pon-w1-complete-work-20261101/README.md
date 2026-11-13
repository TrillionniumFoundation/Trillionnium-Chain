# W1 complete-work evidence, 1 November 2026

This bundle preserves four exact-source native CI runs, their successful cost captures, and their unsuccessful service experiments. The final source selects the complete `FullLimb` verifier by default and passes the recorded semantic, formatting, and strict lint gates. **All four W1 workflows conclude `failure`: neither service job passes in any run. The separate final recent-batch CI repair passes all four lanes.** These observations support an implementation comparison and document an unresolved service limitation. They do not establish W1 work hardness, resource fairness, public-network readiness, deterministic finality, or production activation.

The code under review is [PR #675](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/675), pinned to the measured final head `7c5caf5bce1396976808a0f504c4163fbc1aed44` after the default switch `8327719ebd90ad08c1d66bc10f6c6fd79d7c0b47`. The evidence branch descends from that source. Evidence commits preserve observations; they do not make an unexecuted code revision inherit a previous run's results. Consensus remains Nakamoto-style: independent block validation, required-target cumulative work, difficulty adjustment, and probabilistic confirmation. Model scores and claimed FLOPs add no chain weight.

## Exact sources and workflow outcomes

Each run contains four cost lanes per family: x64 and ARM64, each on the head and prospective merge. Head and merge are distinct commits with the same source tree within the corresponding run. A prospective merge is a tested integration candidate, not evidence that the code was merged or activated.

| Run | Head commit | Prospective merge commit | Shared source tree |
| --- | --- | --- | --- |
| [41297071118](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41297071118) | `8d9a7015cadd39780c4a047b5a36e0fd4d5f494b` | `bc2ed69f8aa9c53b07a57efbd88342d3234c1a87` | `721b601aca93a069d3d9d20e1502983789924877` |
| [41297714882](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41297714882) | `e885a4a284d83019077c9b8f3420d39988a11eef` | `48b7a10a9950278815cfa002a3369a5763329944` | `92e722c38ad4daa206be3d4dfd57d6955c580551` |
| [41298626837](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41298626837) | `8327719ebd90ad08c1d66bc10f6c6fd79d7c0b47` | `a7169139ce2a24f0d582ac348be8f74d56d44f9f` | `7b3bf58b08cf59ba1466059f3e0d5a7d8a96e74a` |
| [41299973417](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41299973417) | `7c5caf5bce1396976808a0f504c4163fbc1aed44` | `c2d5f9ad0ed9402a919e4c87be3825f9aa91837d` | `fef6125b338e5697896c0a32d0488458d8d93244` |

| Run | Eight cost jobs | Cost campaign captures | Two service jobs | Workflow |
| --- | --- | --- | --- | --- |
| Initial candidate | 8 `failure`, from formatting gates | 12 `PASS` captures retained | 2 `failure` | `failure` |
| Formatting fix, `e885a4a2` | 8 `success` | 12 `PASS` captures retained | 2 `failure` | `failure` |
| Default FullLimb, `8327719e` | 8 `success` | 12 `PASS` captures retained | 2 `failure` | `failure` |
| CI binding follow-up, `7c5caf5b` | 8 `success` | 12 `PASS` captures retained | 2 `failure` | `failure` |

The twelve captures are four original false-trace campaigns, four explicit full-limb false-trace campaigns, and four complete legal-strategy campaigns. They are not twelve successful jobs. In the initial run, the campaign steps still executed and retained native output after formatting failed; other controls were skipped. The two service failures were actual executed business-target failures, separate from formatting. Later repairs preserve those earlier failures and do not relabel the initial workflow as successful. See the [initial](run-41297071118/workflow-jobs.json), [formatting-fix](run-41297714882/workflow-jobs.json), [default-switch](run-41298626837/workflow-jobs.json), and [final follow-up](run-41299973417/workflow-jobs.json) job records.

The [recorded final-head workflow snapshot](final-workflow-snapshot.json), observed at **11:27:26 UTC on 1 November 2026**, does **not show a passing full required workspace**. Required/priority runs remain in progress; W1, the original native campaign and CodeQL export include failures. The finality reference run succeeds after one unchanged-source retry of an installation failure. The [earlier 11:17:41 snapshot](workflow-snapshot-111741.json) remains retained. Targeted package tests, examples, and lint commands do not establish all required workspace gates. No merge or deployment qualification follows from the eight successful cost jobs.

## CI binding correction and separate workflow failures

The fourth commit changes only `.github/workflows/pon-recent-batch-acceptance.yml` and `.github/workflows/pon-w1-work-security.yml`. Every Rust, model, reader, configuration, lockfile and other tracked byte equals `8327719e`. The separate recent-batch workflow had retained two old query-model blob pins and a 14-test result check after this continuation added seven tests. All fourteen original test method bodies are unchanged. The correction binds the actual module and test blobs and requires all **21** tests; it removes no source check or test. Its sixteen exact source pins were recomputed before publication.

The W1 workflow now also triggers on that related source-binding workflow, and each legal lane captures its own locked Cargo metadata graph. The first three runs' missing legal metadata graphs stay missing in their records. The fourth run must provide eight actual graphs rather than manufacturing earlier evidence. New execution is bound to `7c5caf5bce1396976808a0f504c4163fbc1aed44` and its actual prospective merge.

The earlier `8327719e` recent-batch run failed before compiling because of those stale pins. Its separate original native campaign executed all nine 30-second phases and failed its original finite confirmation target, including the no-attack baselines. Four failed required-baseline lanes built successfully and reported `CONFIRMATION_TARGET` after their scoped native checks passed. These service observations do not establish a kernel regression or improvement without a suitable control; they remain failures. Full-project results are never inferred from the targeted W1 cost matrix. The [separate-workflow triage report](other-ci-8327719/triage-report.json), [Chinese conclusion](other-ci-8327719/conclusion.zh.txt), and [retained capture index](other-ci-8327719/RETAINED_CAPTURE_INDEX.json) preserve nine complete failing job logs and all 2,202 members of five additional artifacts. Original ZIP container bytes are excluded; their observed hashes and every retained member hash remain recorded.

### Finality installation failure and single retry

The [finality run 41299973511](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41299973511) first failed on its ARM64 head runner while installing Rust 1.95.0: rustup reported a partially installed toolchain and a conflicting `bin/cargo-clippy`, then rolled back before native compilation. The same run's ARM64 merge lane succeeded. One retry of the failed job, using unchanged source, workflow, toolchain version, limits and predicates, completed release compilation, all four required native selectors, the original hot/disjoint4/growth pipeline, counter recomputation and final source recheck. The workflow reports attempt 1 `failure` and attempt 2 `success`.

The [two-attempt triage report](finality-install-retry/triage-report.json) and [public file index](finality-install-retry/PUBLIC_EVIDENCE_INDEX.json) preserve all three complete logs, both attempts' metadata, the exact workflow and the first failure. These are complete log/readback observations; finality artifact contents were not downloaded or independently recomputed. This installation failure does not demonstrate a runtime algorithm regression, and its successful retry does not settle the separate service failures.

### CodeQL export remains incomplete

The separate [CodeQL export run 41299973434](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41299973434) fails its original 1,200-second completion gate. Across 39 retained polls, the head and prospective-merge check responses contain no check runs, and the PR analysis responses contain no analyses. Its source checks and sixteen exporter controls pass; its receipt still correctly records `complete=false`. This is an incomplete exact-source analysis export, not evidence of a reported vulnerability, a successful security scan, a compiler failure or a service measurement. The retained receipts do not establish why the upstream analyses or checks are absent. No gate, timeout or source was changed, and this exporter was not retried.

The [CodeQL triage report](codeql-export/triage-report.json) preserves this boundary. Its [capture index](codeql-export/RETAINED_CAPTURE_INDEX.json) binds all 205 original artifact members, including the polling records and incomplete receipt, plus the separately retained full failed-job log, metadata and exact workflow/exporter source. Original ZIP container bytes are excluded and their measured digest is retained. This failure remains a separate blocker to claiming complete security-analysis evidence.

## Final exact-source observations

The [final native log readback](run-41299973417/native-log-readback.json) again records 101 W1 tests, six fuzz semantic tests and three historical rejection-example tests in every false-trace lane, plus six legal-example tests in every legal lane. Formatting and the corresponding strict Clippy commands pass. The [final provenance report](run-41299973417/provenance-report.json) independently verifies all eight original cost ZIPs, twelve exact-reader results, and **eight actual retained Cargo metadata graphs**. Each graph has 174 resolved packages and 26 workspace members; two raw graph hashes reflect job path differences. Every graph is checked against the exact lockfile and the measured target.

The repaired [recent-batch run 41299973392](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41299973392) succeeds in all four head/merge × x64/ARM64 lanes. Its [native log readback](recent-ci-repair/native-log-readback.json) confirms the two updated source pins, all 21 query tests, subsequent native controls, `trnm-pon-node --all-targets --all-features -- -D warnings`, and source rechecks. Original ignored fields and reprinted/subprocess summaries remain visible; no fabricated independent-test total is produced. [The retained log index](recent-ci-repair/READBACK_INDEX.json) covers complete logs and API metadata, not the contents of this separate workflow's artifact ZIPs.

### Final rejection economics and legal-strategy result

The [final performance summary](run-41299973417/performance-summary.json) and [integer rejection-ratio record](run-41299973417/default-production-rejection-ratios.json) retain 103,808 native verifier calls, zero semantic alerts, 200,136 paid legal attempts, and 4,584 false-trace hash attempts. Repeated prefixes and proofs are not independent observations. The two modes below remain separate timed campaigns, each using its own complete attacker-cost denominator and the default `production` column:

| Final-source mode | x64 head | x64 merge | ARM64 head | ARM64 merge |
| --- | ---: | ---: | ---: | ---: |
| Original four paths: receiver / attacker CPU | 22.954981 | 23.011638 | 22.993044 | 21.891525 |
| Explicit five-path comparison: receiver / attacker CPU | 19.631661 | 20.321783 | 22.068586 | 20.744176 |

The four-path whole-lane range is 21.891525–23.011638; its per-material aggregate range is 18.932164–30.350465. The five-path ranges are 19.631661–22.068586 and 18.158313–27.078307 respectively. **Per-material means the sum of eight actual sample cohorts: eight setups and 32 searches**, followed by division of integer sums. The compact record separately retains individual `(class, sample)` extrema; those are not substituted for material aggregates. Every reported range remains above the original `<= 1` primitive rejection criterion. No cross-mode average or causal speedup is claimed.

The frozen dispatcher costs 6.639830%, 2.370382%, 3.690606%, and 3.701070% more CPU than prepared-generic on x64 head, x64 merge, ARM64 head, and ARM64 merge respectively. It remains experimental. Default and explicit FullLimb share the same arithmetic. Old limb is faster at eight default comparison positions and two explicit FullLimb positions, involving nine distinct cohort positions; all are retained. Earlier Intel aggregate counterexamples remain historical evidence.

### Final original-resource service result

The [final service report](run-41299973417/service-report.json), [Chinese conclusion](run-41299973417/service-conclusion.zh.txt), and [comparison to the default-switch run](run-41299973417/comparison-to-8327.json) independently replay the exact `7c5` readers. Both retained native binaries hash to `5c95269910f98cb10ec026070ac30a4f4c25d804707766c8950946e31af34529`, identical to the measured default-switch binaries. Equal binaries do not make different hosts into a causal timing control.

| Final lane / fixture | Baseline depth-six confirmation | Pressure seventh honest ACK | Received Transcript refusals | Pressure independent confirmations |
| --- | ---: | ---: | ---: | ---: |
| Head / original | 3.492119 s | 2.351921 s | 201 | 0 |
| Head / fresh | 3.492283 s | 2.647003 s | 175 | 0 |
| Merge / original | 3.575088 s | 2.443031 s | 192 | 0 |
| Merge / fresh | 3.578850 s | 2.653796 s | 168 | 0 |

Every pressure receiver accepts all seven honest blocks and stores no attack input. Each independent client fetches one packet but fails local History import with `PUBLIC_REQUEST_DEADLINE`; it stores no post-genesis block and stays at active height zero. All four pressure confirmations fail. The previous merge-fresh network-stage exception is not inherited by this run. Original four-second, sixteen-worker, six-depth and Host limits remain. No resource guard or business predicate is removed to obtain a successful report.

## Native checks on the default-switch source

The [default-switch native log readback](run-41298626837/native-log-readback.json) matches actual test-result lines to their executing targets and retained log hashes. It records the following counts in each applicable lane, with zero failed or ignored tests:

| Scope | Tests per lane | Additional gate |
| --- | ---: | --- |
| W1 primitive module, four false-trace lanes | 101 | Strict primitive library/test Clippy |
| Native work-certificate fuzz semantics, same lanes | 6 | Existing semantic gate retained |
| Historical `pon_rejection_cost` example, same lanes | 3 | Strict example Clippy |
| `pon_w1_legal_strategy_v1`, four legal lanes | 6 | Strict legal-example Clippy |

The legal example's six tests comprise **four legal-strategy tests and two shared material tests**. Reporting four would omit executed tests; reporting six newly added legal tests would misdescribe their scope. Formatting also passes. The [preceding native readback](run-41297714882/native-log-readback.json) records its own 101/6/6 gates; the additional three-test historical-example gate belongs to the default-switch and final follow-up runs.

Runners retain exact source checks, locked Cargo inputs, build/profile evidence, ELF architecture, and binary hashes before and after execution, including the retained executable. In the first three runs, four false-trace jobs retain complete Cargo metadata graphs but the four legal jobs do not retain separate metadata graphs. Their exact source, locked commands, configuration, compiler and dependency build output are checked; missing original graphs are not reconstructed as captured evidence. The legal campaign requires all 30 fixed shards and preserves each shard's streams and failures. Its 300-second per-shard limit remains unchanged; a failed shard does not erase later observations or permit an incomplete grid to pass. These controls establish retained-record consistency, not independently trustworthy clocks or universal hardware behavior. The [default-switch provenance report](run-41298626837/provenance-report.json) records that distinction.

## Implementation meaning and preserved comparisons

FullLimb extends exact limb arithmetic through the complete verifier. It retains the same field relation, transcript, product, proof bytes, challenge and ticket binding, rejection order, and cancellation checkpoints. A false claimed trace still requires transcript replay before `Transcript` rejection; a matching transcript still requires the complete product comparison. Faster arithmetic does not supply a new anti-Sybil premise. The [default-switch review](default-switch-review.json) records unchanged regions, public-entry behavior, cache distinctions, and callback ordering; it is a static review supplemented by the native results above.

The historical `pon-work-rejection-cost-v1` diagnostic keeps its `production-transposed` meaning through explicit `verify_transposed` and `verify_transposed_with_progress` APIs. Its schema and denominator remain fixed. In source-bound newer reports, `production` means the default verifier at the measured source: Transposed in the first two runs, FullLimb in the third and fourth runs. On both `8327719e` and `7c5caf5b`, **`production` and `full-limb-experimental` execute the same kernel**. Differences between those labels cannot be advertised as an additional algorithmic speedup. Prepared producer selection and the opt-in arithmetic-fact cache's explicitly transposed arithmetic remain separate paths.

The initial [performance readback](run-41297071118/performance-readback.tar.xz) retains a counterexample to any uniformly-fastest claim: on its Intel x64 head, complete-limb aggregate CPU for legal acceptance and late product rejection was about **3.8% higher than the older transcript-only limb path**. Complete limb nevertheless used less aggregate CPU than that run's default Transposed verifier. Its whole-lane receiver rejection CPU divided by complete measured attacker CPU was approximately **19.2–22.0**; the corresponding per-material range was approximately 18–26. Those are different aggregations.

The [e885 performance summary](run-41297714882/performance-summary.json) reports complete-limb false-trace CPU savings of approximately **9.19–18.99% against Transposed**, with whole-lane rejection/attacker ratios of approximately **18.78–21.21**. Four cohorts remained slower than the older limb path. The frozen public dispatcher used approximately **1.69–3.68% more aggregate CPU than prepared-generic in all four legal lanes**. This is a retained negative strategy result, not a reason to select a faster sample after observing its timing.

The default-switch run's source-specific cost record is its [performance summary](run-41298626837/performance-summary.json). It retains 103,808 complete verifier calls, zero semantic alerts, 200,136 charged legal-strategy attempts, and 4,584 false-trace hash attempts across twelve captures. These are executed counts, not independent sample counts. The dispatcher costs 1.66–3.70% more CPU in the four complete legal-lane aggregates. Six cohorts favor old limb over the default entry and eight favor it over the explicit full-limb entry; all fourteen negative positions remain in the record.

The [default-production rejection ratios](run-41298626837/default-production-rejection-ratios.json) use the `production` column and complete integer CPU sums. The four-path and five-path modes are separate measurements with separate denominators:

| Default-switch mode | x64 head | x64 merge | ARM64 head | ARM64 merge |
| --- | ---: | ---: | ---: | ---: |
| Original four paths: receiver / attacker CPU | 20.746506 | 22.386952 | 21.923875 | 22.255450 |
| Explicit five-path comparison: receiver / attacker CPU | 17.796037 | 19.863060 | 20.582070 | 21.002607 |

The respective per-material ranges are 16.463665–30.248471 and 16.447169–26.588794. They remain above the unchanged `<= 1` rejection-economics criterion. No modes are pooled or compared as a causal speedup. Recorded attacker cost includes evidence-retention overhead that an optimized attacker can avoid; it is neither the cheapest attack cost nor an upper bound on network amplification.

Earlier percentages are not transferred to the changed default. All quoted ratios use complete measured sums, including setup and unsuccessful attempts in the defined interval. They are local primitive observations, not a public attack amplification factor, a cheapest-adversary lower bound, or a causal explanation for service performance across different hosts and boots.

## Legal strategy coverage and sample limits

The frozen grid combines five public material classes—full-rank field, zero, continuity maintenance, and left/right one-zero rank-one—with two targets and reuse horizons of 1, 8, and 64 winners. Prepared-generic and frozen-public-dispatch are complete executable strategies. Selection, preparation, misses, and actual reused searches stay in their cost denominators. Legal acceptance and a mutation of the last product word are checked across the retained verifier entries; successful ticket acquisition alone is insufficient.

There are **two legal samples per fixed class × target × horizon shard, below the unchanged requirement of eight**. Repeated proof identities, overlapping search prefixes across horizons, head/merge repetitions, and repeated verification calls do not manufacture independent samples. Architecture coverage does not by itself establish independent hardware qualification. A slower frozen dispatcher narrows one measured candidate; it neither proves generic production optimal nor excludes cheaper structured, preprocessed, batched, accelerated, or otherwise legal strategies. Model improvement remains a separate empirical question from computation correctness and work cost.

## Default-switch service failures under the original envelope

The [default-switch service conclusion](run-41298626837/service-conclusion.zh.txt), [structured report](run-41298626837/service-report.json), and [complete readback](run-41298626837/service-readback.tar.xz) retain four scenarios: original repeated-packet and fresh-challenge traffic, on head and prospective merge. Default FullLimb actually executes in public Submit and independent History verification. These fixtures use `PublicServer::new` without arithmetic-fact or rejection caches.

All four baselines reach independent active height 7 and confirmation depth 6 within the original four-second window. Under pressure, **all four independent clients record zero confirmations**. The receiver accepts the seven legal business blocks and reaches height 7 with cumulative work 14; attack packets are not stored. ACKs, receiver state, independently stored blocks, independently active height, and confirmation are distinct outcomes.

Both head clients store no post-genesis blocks. Both merge clients store the first two post-genesis blocks but keep active height zero. Head repeated, head fresh, and merge repeated fail local History import with `PUBLIC_REQUEST_DEADLINE`. Merge fresh has `verification_errors=[]` because its third History request never reaches local import: it begins at **3.952986514 seconds**, returns at **4.049417909 seconds** with `FRAME_DEADLINE`, reports `failed_stage=challenge`, and returns after the business window. An empty local verification-error list therefore does not signify service success.

The original diagnostic exits zero after checking safety/accounting invariants, while the reader rejects `CONFIRMATION_TARGET`. The fresh native process reaches its business assertion and exits 101; its wrapper reports `FRESH_NATIVE_PROCESS_REQUIRED`, while direct report readback rejects `FRESH_BUSINESS_TARGET`. These are not missing executions or compilation failures.

The envelope remains four seconds, 16 attack workers, and a shared parent cgroup with `cpu.max=25000 100000`, zero burst, 2 GiB memory, no swap, and 256 PIDs. Controller, receiver, attacker, reader, and independent verifier share that 0.25 CPU allocation. Whole-wrapper CPU and throttling cannot be assigned to the receiver or divided by a single four-second phase. Application meter refusal and clock-failure counts are zero; sampled ending credit stays near its two-second cap. These observations do not establish that credit never fell between samples. Work-started/finished counters include cancellation; only explicit `WORK:Transcript` receipts directly establish completed transcript rejection.

Six confirmations here remain probabilistic policy observations, with `finalized=false` and `execution_authority=false`. They are unrelated to a model-evaluation quorum and do not restore the retired PoCO-BFT consensus design.

## Conditional resource-to-chainwork correction

The [pinned cost/DAA analysis](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8327719ebd90ad08c1d66bc10f6c6fd79d7c0b47/docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md) leaves consensus accounting unchanged. With `M=2^256`, `d=T+1`, and `w=floor(M/d)`, an ideal uniform ticket gives expected credited work per complete legal attempt

`eta(T) = d * floor(M/d) / M`.

For `1 <= T <= P` and `k=floor(M/(P+1))`, the exact bound is `k/(k+1) < eta <= 1`. If `q` is resource share and `s` is the attacker's complete-attempt rate per resource relative to the honest rate, the conditional mean-work share is

`q_effective = q*s*eta_A / (q*s*eta_A + (1-q)*eta_H)`.

If `s` already measures credited-work throughput, it already includes the efficiency ratio. At equal targets the adjustment cancels; both legal-campaign targets have `eta=1`. The bound `q < k/(k+(k+1)*s)` is sufficient for honest mean-work dominance in this restricted constant-rate model. At the development limit, `k=2`; with `s=1`, the sufficient condition is `q<2/5`, **not a necessary or universal 40% security threshold**.

Targets derive from actual branch ancestors. The arithmetic does not show that an attacker can obtain and sustain arbitrary differing targets, pay transition and withholding costs, or win a real DAA attack. Exact rational and small-width exhaustive tests check the model, not a W1 cost lower bound, common prefix, or finality probability.

## Archive layout and verification

The [initial](run-41297071118/CAPTURE_INDEX.json), [formatting-fix](run-41297714882/CAPTURE_INDEX.json), [default-switch](run-41298626837/CAPTURE_INDEX.json), and [final](run-41299973417/CAPTURE_INDEX.json) capture indexes map every original artifact to `artifact-<id>-contents.tar.xz`. **All artifact file members are retained**, including failed captures, streams, manifests, and binaries. The original ZIP containers are not included. Their observed hashes and sizes are recorded separately; extraction and recompression do not reproduce the original ZIP hash.

Every run directory contains `workflow-jobs.json`, `workflow-artifacts.json`, `workflow-job-logs.tar.xz`, `performance-readback.tar.xz`, `service-readback.tar.xz`, `service-conclusion.zh.txt`, and `service-report.json`. The three later runs additionally expose `performance-summary.json`, `provenance-report.json`, and `native-log-readback.json`. Archive member manifests in `READBACK_INDEX.json` preserve the derived readbacks separately from native captures. Root-level [validation](validation.tar.xz) and `VALIDATION_INDEX.json` retain supporting checks.

Run the included verifier from this directory:

```sh
python3 verify_archives.py .
```

[FILE_INDEX.json](FILE_INDEX.json) and [SHA256SUMS](SHA256SUMS) bind the published files. [verify_archives.py](verify_archives.py) checks their identities, opens the archives, and verifies complete member sets, sizes, and hashes. It performs no native W1 execution. Matching bytes preserve the evidence and its failures; they do not convert finite observations into work-hardness, service, workspace, or activation acceptance.
