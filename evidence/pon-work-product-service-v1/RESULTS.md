# W1 exact task-product reuse and instantiation/service boundaries

## 1. Outcome and unchanged standards

This stage implements an **opt-in receiver verification optimization** that retains a fully verified AB product across fresh W1 challenges for exactly the same complete canonical A/B bytes. Every call still recomputes its current noise and all 512 transcript tiles and checks its current task, ticket, target, trace and product claim. The ordinary verifier and Node admission remain unchanged.

Both preregistered native jobs completed. Their original 56 full proofs passed 112 native verifier calls and complete independent scalar replay. Observed raw/facts wall ratios on the 19 product-fact hits in each job were **1.301718 and 1.416670**. Across all 28 cases per job, including misses plus cache creation/destruction, the ratios were **1.211463 and 1.262542**. Every observation, including five slower cache-miss calls, is retained. These are finite observations on one nonexclusive x86 host, not a CPU ratio, miner work floor, Node TPS or production advantage bound. [Analysis](analysis.json), [complete readback](readback.json), [independent reviews](independent-reviews.json)

Two additional mathematical results establish the limits of specific actual-instantiation inference routes and a conditional service-to-honest-growth/private-deadline interface. They do not instantiate actual SHA or qualify a production chain. **O01–O04 and O06 remain OPEN; O05/O07 remain conditional and unadopted.** Original closure standards and pure matrix priority are unchanged. Hosted CI was neither inspected nor executed. [Blocker ledger](blockers.json)

## 2. Exact frozen source and registered experiment

Measured commit: **`b6f2322dacc4a23ec43e3207be008614e07c60b7`**. Tree: **`895b472f7a2b8c532081a0dea4c021e1b30cb9a1`**. Parent: `5301a319d4011f24f808f8644583cb4322cdbc97`. Report publication does not replace the source that ran. The [two-job plan](../../formal/pon-nakamoto-v1/experiments/w1_task_product_plan_v1.json), producer, reader and controls were frozen before either measurement. There was no pilot timing, resampling or post-result algorithm change.

| Pin | SHA-256 |
| --- | --- |
| Registered plan | `f44e98f40bd9d3a85ed3e61024652d7b6e03b9dde593fc02e1039ad4961a9dc3` |
| Fresh retained executable | `e8303ab882d4c19851ebbc626c13c0a69646a816824e8a6e45ffa597b78a872e` |
| Actual campaign manifest | `d5be47140723a216e8b3e505a4fd19f21077b86e519853644eb91d19813bee28` |
| Complete scalar readback | `cce5a5275827625149a660f9bd9bd440e2ef44b22416e26052f24dc6f1a2dc91` |
| Independent actual-results review | `8e4b56c3d6c3e6a156f702370665455b89dac1c46ac39ec291fd11f6e055de42` |

The executable was built afresh with Rust 1.95.0, locked offline release dependencies and one build job. Before/after native collection, all 5,025 tracked entries and 700,344,288 tracked bytes matched the exact Git source. The successful reader checked **434 transitive scripts/formal/config files, 7,304,507 bytes**, against frozen Git blobs before and after complete replay. Source-set SHA: `90745571e5862c4bf34bdc5f7cb6fb5fe0d935c1c43e42ae76379571c6773367`. It additionally checked the exact build artifact against original Cargo output and the retained 623,240-byte executable. These bindings are not host, compiler, interpreter or clock attestation. [Source pins](source-pins.json), [reader receipt](readback-run.json)

## 3. What can be reused safely

For the current field relation, let E=EL ER, F=FL FR, A'=A+E and B'=B+F. The original full transcript gives C'=A'B'. Product correction computes

\[
C'-(AFL)FR-EL(ERB')=AB.
\]

AB is independent of the current challenge. The [new task-product owner](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts.rs) therefore stores only the positive AB result after a complete successful original verification and the final cooperative cancellation checkpoint. It uses all 32,768 canonical A/B bytes as the key and retains the 16,384-byte product. Equal products under different input bytes do not alias.

A hit does not cache a transcript or acceptance verdict. It still checks all current input fields, the current task/ticket/target and all 512 fresh transcript tiles, then compares every current C byte with the positive product. A miss performs the original correction once and uses that recovered result; it does not pay for a second AB multiply. Task leases, parents, rewards, transaction execution, model quality and adoption remain outside this mathematical fact owner.

The owner has 1–64 slots and caps retained Rust object storage at 4 MiB. It uses a bounded nonblocking mutex access; contention falls back to fully accounted original arithmetic. It creates no helper work and makes no single-flight guarantee. Cancellation or invalid work cannot publish a new fact; poison fails unavailable. Tests cover current-claim mutation, exact-key isolation, strict target boundary, cancellation, eviction, contention, concurrent callers and retained storage. [Contract](../../docs/protocol/pon-nakamoto-v1/details/W1_TASK_PRODUCT_FACTS_V1.md)

### Exact source-level multiplication count

For N=64,R=8, the following count applies to this transposed implementation's matrix products:

| Component | Raw or fact miss | Fact hit |
| --- | ---: | ---: |
| Two challenge-noise products |65,536|65,536|
| Complete transcript partial products |262,144|262,144|
| Four correction products |131,072|0|
| **Sum in these matrix kernels** |**458,752**|**327,680**|

A hit removes 131,072 scalar multiplications, exactly 2/7 of this subtotal. SHA, reductions, checks, copies, indexing, lookup and other costs remain. This is not a 28.57% total physical-cost guarantee. Across both measured comparison paths, the 38 fact hits account for 4,980,736 fewer such multiplications; proof generation and reference/replay work are separate. The existing miner already had fixed-AB preparation reuse: this stage does not newly claim that miner saving.

## 4. Complete registered workload and identities

Each seed covers zero, identity, rank-one A, sparse, near-field-boundary and deterministic dense materials, with four fresh challenges per family. Each main family gets a new capacity-two owner. A separate capacity-one sequence zero→identity→zero→zero requires miss→miss→miss→hit. Owners are destroyed between groups.

| Scope | Full proof records | Raw calls | Facts calls | Fact misses | Fact hits |
| --- | ---: | ---: | ---: | ---: | ---: |
| Main families, per seed |24|24|24|6|18|
| Eviction, per seed |4|4|4|3|1|
| One complete job |28|28|28|9|19|
| **Two complete jobs** |**56**|**56**|**56**|**18**|**38**|

There are 100 original JSONL rows per job and 56 distinct challenges across both jobs. The union has seven task-material identities: five common structured families and a separate dense material per seed. The reader field named `distinct_task_products` counts task identities; this report does not reinterpret it as a proof of product distinctness. The 112 accepted verifier calls are two checks of each original proof, not 112 different proofs or rewarded tickets.

Every original full PNW1 proof is 49,188 bytes. All accepted measured calls retained 512 transcript tiles and 128 pre-product row callbacks; raw calls and fact misses retained 200 correction rows, fact hits zero. Aggregate callback observations are 57,344 transcript tiles, 14,336 pre-product rows and 14,800 correction rows. In this particular sample all noise callbacks numbered 256, totaling 28,672; the reader derives actual noise expansion from each challenge and does not assume 256 for arbitrary challenges.

Target bytes are all`ff`. This is a full-relation verification experiment. The example does not register these materials as eligible tasks under a real Node parent. **Node admissions, canonical growth and newly credited rewards are zero.**

## 5. Observed wall-time comparisons

Every ratio below is sum(raw verifier-call wall)/sum(facts verifier-call wall). Larger than one means the facts path used less wall time in those observations. “Cold” means product-fact miss, not a cold CPU, process or filesystem. Scalar proof generation/reference checking has already touched the material before either measured arm. Cache ownership is distinct from physical cache temperature.

### All registered cases, including eviction

| Seed | Fixed per-case arm order |9 misses|19 hits|All28 calls|All28 plus cache create/drop|
| --- | --- | ---: | ---: | ---: | ---: |
| 8101 | raw → facts | 1.094889 | 1.301718 | 1.220980 | 1.211463 |
| 8102 | facts → raw | 1.033460 | 1.416670 | 1.262968 | 1.262542 |

### Main families and eviction kept distinguishable

| Seed |6 main misses|18 main hits|All24 main calls|All4 eviction calls|
| --- | ---: | ---: | ---: | ---: |
| 8101 | 1.132176 | 1.304746 | 1.251103 | 1.070189 |
| 8102 | 1.026398 | 1.343421 | 1.243198 | 1.360302 |

Main-only ratios including their own owner creation/destruction are1.239457 and 1.242733. The two jobs' pooled all-case/lifecycle ratio is 1.232660; the pooled main-only/lifecycle ratio is 1.240813. Pooling sums recorded durations and provides no additional independent sample. One eviction hit in seed8102 has ratio 2.781504; it is retained as a single observation, not promoted to a general performance promise.

### All five slower facts observations

| Seed | Case |Raw wall ns|Facts wall ns|Raw/facts ratio|
| --- | --- | ---: | ---: | ---: |
| 8101 | main-zero-0 | 631,888 | 802,352 | 0.787545 |
| 8101 | main-sparse-0 | 764,605 | 859,918 | 0.889160 |
| 8102 | main-zero-0 | 531,419 | 888,475 | 0.598125 |
| 8102 | eviction-0 | 542,776 | 562,295 | 0.965287 |
| 8102 | eviction-1 | 646,120 | 822,351 | 0.785699 |

Thus 51 of 56 observed cases were faster through the facts path, while five misses were slower. All 38 observed hits were faster in this finite campaign. Opposite fixed orders across two seeds are not randomized hardware trials or confidence bounds. No favorable instance was retained at the expense of a failed or slower one. [Full per-case analysis](analysis.json)

## 6. Complete accounting, residuals and memory scope

Each measured `Instant` interval includes the verification function's real progress accounting and cache operation, but excludes subsequent comparison, product hashing, JSON encoding/output and final destruction of the returned object. Owner construction/destruction, material creation, proof generation and scalar reference verification have distinct intervals. Everything else remains in the observed residual.

| Scope, nanoseconds unless stated | Seed8101 | Seed8102 |
| --- | ---: | ---: |
| Material/task preparation | 2,954,888 | 2,872,154 |
| Scalar proof generation | 22,601,440 | 15,979,845 |
| Scalar reference verification | 26,363,216 | 17,484,040 |
| Cache construction/destruction | 153,579 | 4,717 |
| All accounted operation wall | 95,492,339 | 67,958,908 |
| Unallocated native wall residual | 24,263,185 | 11,361,838 |
| Native wall before final output | 119,755,524 | 79,320,746 |
| Whole waited command wall | 133,803,525 | 88,868,397 |
| Whole waited command CPU | 119,215,000 | 80,684,000 |

The wall identity is exact: accounted operation wall plus the nonclamped residual equals native wall before final output. Final JSON/exit and wrapper work are outside that endpoint. Whole-child CPU totals 199,899,000ns across both jobs and includes preparation, both arms, reference checks, output and teardown. It cannot be apportioned into arm CPU using wall fractions. The rounded GNU-time CPU observations have the fixed 20,002,000ns reconciliation allowance; they do not replace native wall observations or provide per-arm CPU.

The main owner retained 98,368 software bytes and eviction owner 49,212. There are fourteen owner lifecycles across both jobs, but at most one owner is alive at a time. Adding all lifecycles would misstate peak retention. Allocator overhead, verifier workspace, copies, returns and process RSS are outside this object measure. GNU-time command max RSS and the collector's cumulative waited-child max RSS have different scopes and are not summed.

The visible host is AMD EPYC 9V74 x86_64, with nine logical CPUs exposed and each native child pinned to CPU 0. It is nonexclusive and operated by one operator. No actual ARM, GPU, energy, memory-bandwidth, WAN transfer or independent-operator result was acquired. Cumulative cgroup history is retained in the hardware observations; it is not attributed to this short campaign. [Readback hardware and resource fields](readback.json)

## 7. C38: three actual-instantiation shortcuts do not supply the missing bound

The [instantiation note](../../docs/protocol/pon-nakamoto-v1/details/W1_INSTANTIATION_BARRIERS_V4.md) proves three bounded findings and states a narrower actual-W1 obligation. Twenty-four exact frozen controls check finite examples and boundary handling; they do not prove actual SHA hardness.

**Public program versus independent ideal permutations.** A test can compute a selected public SHA round transformation locally, query the proposed oracle once and compare. Acceptance is 1 in the public-program world and 2^-256 for a fresh independent ideal permutation, giving advantage 1−2^-256. This rules out an unrestricted whole-transcript indistinguishability bridge of that form. It is not a collision, preimage, W1 shortcut or actual winning-ticket attack. An inline SHA control likewise computes literal 66/90-byte W1 messages with two scalar compression executions and zero calls through a disabled library API. Zero calls to an observed API does not mean zero work.

**Unspecified hash hardness versus a threshold law.** The hypothetical family H(x)=0^b||R_(n−b)(x) always meets T=2^(n−b)−1, while a uniform n-bit digest meets it with probability 2^-b. Its random image has only n−b bits: the retained generic preimage/collision properties are for that smaller image, not full n-bit concrete strength. This separates unspecified asymptotic hash hardness from the required threshold law. Actual W1 SHA was not replaced.

**Current coarse seeded capacity plus the CDG transfer.** The existing seeded path allowance is m≤P+floor(Q/2049), with m≤G. Using the declared complete-opening checker cap C_comb=Q+3594G for the combined attacker/challenger queries, the following direct-transfer obstruction holds. The3,594 term is a checker upper allowance, not a mandatory per-opening cost lower bound. For gamma=2^-h,h≥2, the generic multiplicative transfer requires P≥6(S+2h)C_comb>G, so the resulting allowance already covers every possible opening. For the additive branch, a nonempty capacity-violation event requires P<G; its loss 12(S+h)C_comb/P+2gamma is then already trivial. The external theorem still holds: its direct use with these interfaces yields an uninformative result. This is not an impossibility theorem for finer seeded graphs, other checkers, direct advice analysis or protocols with justified fresh entropy. The full checker cost cannot be erased merely because the miner does not pay it. [Primary theorem](https://cs.nyu.edu/~dodis/ps/ai-perms.pdf)

A useful actual result must cover a native event with predeclared fixed d and k, E_(d,k)={W≥K0+k and D0≥d}, with global QP,QA,V,G,R caps and unambiguous native candidate identities. Only under the stated event/resource/identity transfer premises could the earlier ideal-model binomial tail plus Join failure be augmented by epsilon_W1,epsilon_cap,epsilon_id. Those losses remain unknown, not zero. Resource conversion must include inline/fused kernels, batches, old banks, failed choices, all tasks/parents and external assistance. Candidate identity fanout-one in that model does not establish global reward consumption. **O01/O02 remain OPEN.**

## 8. C39: conditional service, honest growth and private deadlines

The [service/growth note](../../docs/protocol/pon-nakamoto-v1/details/W1_SERVICE_GROWTH_V4.md) supplies a finite-horizon mathematical connection inside one **joint reference experiment**. It must simultaneously carry honest fresh-valid-trial lower laws and the adversarial capped upper process, with one bounded outside-world failure event. Separate marginal couplings and conditioning on future successful service do not supply this joint construction.

For M=2^256 and a predeclared global exposure cap 1≤C≤M, a genuinely fresh ideal ticket at target T has the lower conditional envelope

\[
\ell_T=\max(0,(T+2-C)/(M-C+1)).
\]

A predeclared nonoverlapping slot guarantees n_j distinct fresh canonical opportunities unless one already won. Its parent is fully validated, reaches at least the honest minimum work frontier at slot start, and has fixed native target within that slot. Complete winning data, ancestors, task material and native admission reach all counted honest nodes before the next slot. Under these hypotheses, conditional slot success is at least 1−(1−ell_T)^n_j; independence or Poisson arrivals is not needed. At most one success contributes to the slot's guaranteed frontier growth. Same-parent siblings are not consecutive chain increments.

For fixed legal target bounds, q_j^-=1−(1−ell_(T_j^-))^n_j and w_j^-=floor(M/(T_j^++1)). For integer h≥1 and z>1, the reference lower-tail bound is

\[
F_H=\min\left(1,z^{h-1}\prod_j[1-q_j^-(1-z^{-w_j^-})]\right).
\]

This bounds minimum visible honest work growth below h at the stated deadline, not a common block prefix. For h=0 the shortfall event is empty; the displayed formula is not used. For a purely private attacker extension initially behind by d0≥0, strict overtake needs D=d0+h+1. With deterministic old winning weight w0, global new-opportunity cap N_A and rho=M/(M−C+1), D>w0 gives

\[
\Pr[\text{private overtake at the fixed deadline}]
\le\min\left(1,F_H+\min(1,\rho N_A/(D-w_0))+\epsilon_{world}\right).
\]

Finite unions need predeclared deadlines. This is not all-fork settlement, competition that absorbs honest blocks, unlimited time or a production confirmation-depth theorem. The actual epsilon_world remains unknown. Actual SHA, physical opportunity guarantees, eligible-parent selection, complete data availability/admission, fixed honest cohort and monotone validated frontier remain premises.

### Why a receiver average or global CPU bucket is insufficient

For a retained FIFO honest flow with an all-window arrival envelope sigma+lambda*u and a valid minimum service curve R[u−L]+, lambda≤R gives delay≤L+sigma/R and sufficient backlog allocation sigma+lambda*L. CPU, bytes and storage need separate justified curves. The leftover construction also requires true backlogged minimum aggregate service and an all-window bound on **executed interference**, including initial backlog and nonpreemptive/unmetered work. Unknown residual blocking cannot be set to zero. [Primary network-calculus tutorial](https://leboudec.github.io/netcal/resources/tutorial-nc-dagstuhl-EPFL-2019-LEB.pdf)

The current global CPU bucket limits/accounted work; it supplies no positive honest minimum share by itself. Exact controls show an upper-quota-compliant schedule with zero honest service and two equal-average schedules with different deadline completion. Invalid transcripts, invalid roots, parser work and rejected requests can consume resources without creating valid tickets. Their service interference requires separate bounds. **O03 remains OPEN.**

## 9. Hepta and alternative mechanisms retain their owners

The separately rechecked Hepta PR 3219 still points to `de133b601e133917cbe1ae03efb3a2ffc06dcd4a`, open and unmerged. The prior exact-source review remains applicable: selected fixed initial SmolLM material exists, while the distinct ordinary initial-only host composition and a real measured ordinary base parent/forward remain absent in the reviewed evidence. Initial parent creation must not require a previously improved child. No new Hepta model execution, independent quality/poisoning test, adoption, rollback or complete cross-node Cell product loop occurred in this stage. [Source review](hepta-source.json)

A positive matrix product, a valid W1 ticket and a model's useful improvement are different facts with different owners. Cached mathematical facts cannot grant task authority, CURRENT/FinalUse or installation. Pure matrix remains primary. If a hybrid floor or ZK wrapper is adopted later, it needs its own binding, failed-work reuse, consumption uniqueness and complete joint-cost/soundness argument. Calling these unadopted options does not close their original conditional obligations.

## 10. Validation and complete failure history

Frozen source passed **188 Rust tests**, with **two original explicitly ignored cost observations** unchanged, plus **255 Python checks**: 177 direct controls and 50+28 canonical checks. Whole-workspace/all-target/all-feature strict release Clippy, fmt, locked Cargo graph, embedded inventory and original source-integrity controls passed. This is not a full-workspace runtime-test claim. Preliminary repeated checks and the first failed canonical attempts are not added to the final test total. [Validation](validation.json)

Nine new native product-fact tests are included in the 188. The 14 new reader controls include actual scalar-proof mutation boundaries; ten additional binding controls use explicitly synthetic grammar fixtures and are not native execution evidence. The actual 56-proof formal replay provides the separate native-data coverage.

The original full-copy source-mutant gate twice failed from disk exhaustion, then passed unchanged after exact retained-evidence deduplication. An archive checker initially rejected hardlink aliases; its original archive/failure remains, and a dereferenced archive was fully verified before build-cache reclamation. Pre-freeze formatting/Clippy fixes and their original logs are retained.

The first formal reader refused 21 preexisting ignored bytecode files at its exact source-file-set gate, before scalar replay. Quarantine recovery encountered storage exhaustion and later extra transfer-temporary paths. The successful recovery used a separate local shared Git clone with every required frozen scripts/formal/config file materialized. It ran the unchanged strict reader, with no exclusions or acceptance changes. Four old cached code objects differed from current source and all four had invalid timestamp/size headers; they were absent from the successful isolated reader. The source-bound reader result is not an interpreter-attestation claim. **Neither native job was rerun.** [Failure history](failure-history.json), [reader receipt](readback-run.json)

Internal independent-agent review checked the two theory directions, collector/reader bindings and every actual native JSONL result. It does not satisfy independent hardware/operator acceptance.

## 11. What remains to close the original obligations

| Obligation | Status | Still required under its original standard |
| --- | --- | --- |
| O01 actual resource→valid opportunity | OPEN | Actual-W1/SHA event argument; real global resource conversion; nonvacuous advice treatment; concrete failure/identity bounds. |
| O02 arbitrary adaptive strategies | OPEN | Actual long-term advice, favorable seeded states, arbitrary kernels/hardware, optional task/parent selection and external help inside a justified cost class. |
| O03 production kappa and chain safety | OPEN | Actual joint lottery/service/DA premises, all-fork settlement, usable numerical parameters and failure-response rules. |
| O04 independent physical costs | OPEN | Real independent ARM/GPU/available specialized execution, energy and memory/network bandwidth evidence. |
| O05 hybrid base work | CONDITIONAL, NOT ADOPTED | If selected, composable binding/reuse/unique-consumption and cost guarantee. |
| O06 Hepta utility/adoption | OPEN | Ordinary initial-host product integration and real independent task/quality/poisoning/adoption/rollback/Cell evidence. |
| O07 ZK ticket amplification | CONDITIONAL, NOT ADOPTED | If selected, actual public-statement/reward identity, multi-proof amortization and soundness/full-cost proof. |

C38–C41 close only their declared bounded subproblems. The next mathematical target is a nonvacuous useful-seeded-opportunity or direct native-advice bound, not an arbitrary small SHA error attached to the current formula. The next service target is an actual retained-honest-flow guarantee with complete interference and DA ownership; relation-kernel speed alone cannot supply it. The missing physical and Hepta acceptance observations require real executions by their proper owners. [Ledger](blockers.json)

## Evidence package

[Delivery manifest](delivery.json) and [artifact index](artifact-index.json) bind all retained formal proof bytes, exact command receipts, observed outputs, executable, theory controls, reviews, failures and recovery records. Reproduction uses the original frozen source and external pins above; arbitrary later report commits are not the measured program. The archive does not claim the prior complete campaigns ran again. Their original archives and ledgers retain their own identities.
