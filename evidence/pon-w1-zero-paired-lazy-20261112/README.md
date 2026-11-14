# W1 cheapest-legal-work baseline: zero paired arithmetic and winner-only proofs

**Status: complete native component observation; work-security qualification remains HOLD; production_activation=false.** This extends the legal strategy set without establishing global optimality, a hardware-independent work floor or production security.

The current campaign combines the specialized zero integer-paired kernel with winner-only proof construction. V5 supported lazy generic FullLimb arms but called the eager legacy zero-paired producer. Five fixed arms now pay actual preparation, all failures, disposal and cleanup. No production default, consensus relation, task authority, target rule, chain weight or reward changes.

**Observed result:** in all four cost cells, the same preregistered `full-limb-sparse-lazy` strategy has the lowest aggregate CPU and wall cost per accepted winner among these five measured strategies. The zero-paired kernel's 152,832 scalar-product operations do not translate into the lowest measured runtime here. Operation counts, observed timing, and a lower bound over all legal algorithms are different claims.

This directory follows the [development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md), [new experiment contract](../../docs/research/PON_W1_ZERO_PAIRED_LAZY_V1.md), [work-cost contract](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_CONTRACT_V1.md), and [work/DAA boundaries](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md).

## Frozen measurement identity

| Item | Recorded value |
| --- | --- |
| Native measurement source commit | `165d286b687e0a73d7fe68148d2179274fc0c0b8` |
| Source tree | `2eb4f5e888a7a02f573d72a2fdf4d5a7cfc352e0` |
| Source state | `committed-clean`; complete tracked-worktree verification |
| Tracked entries / bytes | 28,330 / 2,578,833,390 |
| Original campaign manifest bytes | 403,864 |
| Original manifest SHA256 | `1972cd517095034d809b48f509b53dd0d51d24f1b5d37a71bdd0e7c91a5373f6` |
| Retained native ELF SHA256 | `106475d07ddd75e0eced90b19ec84a7658732951a207bebd764c37f10a1aace1` |
| Native host scope | Linux x86_64; one observed host, not independent hardware replication |
| Evidence publication identity | A direct evidence/docs/corpus child of the native source. Its actual commit is recorded after commit in the external publication receipt and the PR execution ledger; native results remain bound to `165d`. |

The inventory verifies source identity; it does not say every file was compiled. The runner retains source before/after, compiler/ELF, process exits, logs and host observations. These receipts are not unforgeable execution attestation. A later evidence-only commit is not the measured source.

## Implementation and registered experiment

The [zero-paired producer](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs) adds target-aware `attempt` and cancellable `attempt_with_progress`, returning an unverified `Attempt`. Its constructor requires exact canonical A=B=0; unsupported operands are not substituted. Legacy `prove` remains available.

The [native observer](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_zero_paired_lazy_v1.rs) preregisters `full-limb-sparse-eager`, `full-limb-sparse-lazy`, `zero-paired-legacy`, `zero-paired-eager` and `zero-paired-lazy`. The FullLimb comparator uses actual sparse preparation on zero operands. All arms compute the full challenge-dependent transcript. Lazy mode skips losing proof buffers. Eager slices are observed before their producer timer ends; the separate audit hashes all actual 49,188 bytes. The optimization barrier is best-effort, not execution authentication.

Each cell has eight samples and all five arms. T0=`7f` plus 31 `ff` bytes; T1=`07` plus 31 `ff` bytes. Cost cells use H1/H8 actual searches per preparation and a 4,096-attempt cap. Exhaustion/first-hit controls use H1 and a three-attempt cap. Searches stop at the first hit or retain every exhausted attempt; no replacement winner fills a missing result.

Order rotates as `(position + sample) % 5`, without perfect balance. Challenge identity binds task, target, sample, search and nonce, excluding arm/horizon. Across-arm streams must match; nested horizons share correlated prefixes. No per-sample fastest-strategy oracle, cross-target/horizon pooling or independent-sample inference is used.

## Timing results

For each fixed arm/target/horizon, the estimator is **sum of complete producer costs / sum of accepted winners**. Producer cost includes paid setup, every real attempt, losing-buffer disposal, winning-buffer cleanup and prepared-object teardown. Audit/evidence, verifier timing, pre-header material construction, source/build checks and outer process costs have separate scopes. Inclusive search/cohort clocks overlap components and are not added to them. Audit and verification run in the same process; separate intervals do not remove possible cache, allocator or subsequent-performance effects. A zero-winner ratio is `null`, not zero or infinity.

Values below are milliseconds per accepted winner. [Full five-arm results and eight-cohort ranges](cost-results.md) retain all 20 cost rows, including slower observations.

| Cell | FullLimb lazy CPU | Zero-paired lazy CPU | FullLimb lazy wall | Zero-paired lazy wall |
| --- | ---: | ---: | ---: | ---: |
| T0 / H1 | 1.973125 | 2.143376 | 1.978518 | 2.148661 |
| T0 / H8 | 2.414077 | 2.646782 | 2.419570 | 2.651590 |
| T1 / H1 | 51.437078 | 56.326995 | 51.512632 | 56.397523 |
| T1 / H8 | 40.004135 | 44.701399 | 40.065571 | 44.762684 |

The next table uses fixed references. Every ratio is **reference cost per accepted winner / zero-paired-lazy cost per accepted winner**. A value above one means zero-paired-lazy was cheaper in that observation.

| Cell | Legacy / zero lazy CPU | New eager / zero lazy CPU | FullLimb lazy / zero lazy CPU | Legacy / zero lazy wall | New eager / zero lazy wall | FullLimb lazy / zero lazy wall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| T0 / H1 | 1.009910 | 0.995480 | 0.920569 | 1.009834 | 0.995872 | 0.920814 |
| T0 / H8 | 0.996527 | 1.010260 | 0.912080 | 0.997100 | 1.010129 | 0.912498 |
| T1 / H1 | 1.004714 | 1.005895 | 0.913187 | 1.004883 | 1.006218 | 0.913385 |
| T1 / H8 | 1.005845 | 1.002096 | 0.894919 | 1.005862 | 1.002139 | 0.895066 |

Zero legacy/eager differences are about +/-1%, with mixed direction. Eight-cohort ranges provide no confidence interval or statistically stable advantage; they are not pure timer-noise distributions. FullLimb lazy's observed minimum among these five strategies is not a minimum over all algorithms, hardware, materials or horizons.

Independent arithmetic checked eight-cohort sums, winner sums and exact integer ratios. The numeric excerpt is not a complete receipt and lacks sample IDs: it does not independently authenticate pairing, replay W1 or authenticate execution. Original journal/reader receipts retain their separate roles.

## Attempts, materialization and controls

Each cell retains matching attempt/outcome counts across all five arms. The [detailed count table](cost-results.md) reports all misses, eager/lazy materialization and whole-cell setup calls.

Totals reconcile to **240 cohorts, 240 setup calls, 800 searches, 12,840 attempts, 760 hits, 12,080 misses, 40 exhausted searches, 8,008 materialized proofs and 3,280 verifier calls**. The two controls are not ordinary-target cost samples. The zero-winner exhaustion-control rate remains null. The excerpt has cell-level setup counts; missing per-arm fields are not manufactured.

Completion requires both production and scalar-reference verifiers to accept each winner and reject its last-product-word mutant as `Product`. Both replay every exhausted-control miss at maximum target, retaining the original miss identity and granting no original-target credit.

Observed attempts per search differ across horizons: T0 has 1.5 at H1 and 1.875 at H8; T1 has 40.5 at H1 and 32.5 at H8. Cross-horizon cost differences therefore cannot be attributed only to preparation amortization. Comparisons remain within each fixed cost cell.

## User-requested strategy set: coverage and remaining obligations

This maps obligations; **it does not claim eight-class completion**. Historical evidence keeps its own source. No older timing is imported into `165d`.

| Strategy class | Existing executable/specification anchors | Coverage in this campaign | Boundary that remains open |
| --- | --- | --- | --- |
| Zero, sparse, low-rank and diagonal material | [Implementation comparison](../../docs/protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md), [structured producer](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs), [bounded exact low-rank preparation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt/low_rank.rs), [V5 grid](../../formal/pon-nakamoto-v1/W1_RANK_BATCH_V5.md) | A=B=0 only; five fixed arms with actual sparse preparation. | No current nonzero grid, exhaustive strategy set or real-demand frequency estimate. |
| Short-column material with zero padding | [Checkpoint tile material](../../trillionnium/crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs), [operator tests](../../trillionnium/crates/trnm-pon-node/tests/checkpoint_tile_operator.rs) | Not exercised by the zero-only campaign. | Actual 1..64-column extraction, padding, provenance and eligibility remain separate. Valid padded bytes do not prove demand. |
| Preparation across nonce, miner and epoch | [Actual reuse example](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_reused_cost.rs), [zero-task lifecycle](../../trillionnium/crates/trnm-pon-node/tests/zero_task_preparation_lifecycle.rs), [DAA/cost boundaries](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md) | Actual nonce/H1/H8 search reuse; each setup is paid once. | No miner/epoch sharing measurement. Statement binding, retained state and ownership costs remain obligations; replay is not new credit. |
| GPU/ASIC, shared cache and early screening | [Lifecycle cost contract](../../docs/protocol/pon-nakamoto-v1/details/WORK_COST_CONTRACT_V1.md), [receiver admission facts](../../trillionnium/crates/trnm-pon-node/src/ingress/metered_work_facts.rs) | **No GPU/ASIC, shared-cache or early-screening strategy measurement.** One CPU host only. | GPU/ASIC throughput, energy, memory and cache/filtering costs remain unknown. Receiver shortcuts prove no producer cost floor. |
| Do not construct losing proofs | [Target-aware zero producer](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero_paired.rs), [new native observer](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_zero_paired_lazy_v1.rs) | Same zero streams; misses/disposal paid; actual materialized proof bytes audited. | Host-specific costs; winner-only construction neither skips full verification nor proves cheapest search. |
| Cheap fake-transcript search and expensive receiver rejection | [Actual false-trace reuse entry](../../trillionnium/crates/trnm-pon-node/examples/pon_w1_false_trace_reuse_v1.rs), [false-trace contract](../../docs/development/specs/pon/W1_FALSE_TRACE_ACTUAL_REUSE_V1.md), [W2-C receiver research](../../docs/protocol/pon-nakamoto-v1/details/W2_C_RECEIVER_COST_RESEARCH.md) | Product-last/exhaustion correctness controls only. | No current fake-search/rejection, queue, concurrency or network-cost measurement. Invalid tickets earn no valid work but may impose rejection cost. |
| Attacker-selected tasks, sponsor self-traffic and repeated rewards | [Demand evidence contract](../../docs/development/specs/pon/DEMAND_EVALUATION_UPGRADE_V1.md), [demand checker](../../formal/pon-nakamoto-v1/demand_evidence.py), [reward budgets](../../docs/development/specs/pon/REWARD_BUDGETS_V1.md), [native task lifecycle](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs) | No demand/reward campaign; zero consensus credit and payment. | No independent-customer or hidden-common-control proof. Internal transfers are not automatically cost; deduplication, admission and reward lanes require joined evidence. |
| Maintenance when real demand is absent | [Maintenance cost example](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_maintenance_cost.rs), [paired conformance](../../trillionnium/crates/trnm-pon-node/tests/maintenance_paired_conformance.rs), [continuity policy](../../trillionnium/crates/trnm-mvcc-fee/src/continuity_v1.rs) | Not measured; zero-only code cannot substitute for nonzero maintenance. | Current maintenance/ownership/DAA costs remain open; archived costs keep their source. Availability does not prove hardness. |

The DAA document's four-search maintenance/service costs belong to source `4e49725f1b457a422dbb12f620101903c21599d7`, not `165d`. V5's broader strategy/material roster did not run in this zero-only campaign.

## Validation, retained failure and qualification state

| Observation | Recorded result and scope |
| --- | --- |
| Current native crypto library tests | 199 passed; finite component tests |
| New reader controls | 21 passed; synthetic grammar/mutation controls, not native timings |
| Source-integrity negative controls | 43 passed; source-guard behavior, not W1 hardness |
| PQ corpus | 60 passed; its named corpus, not a global PQ or C5 qualification |
| Formal six-cell native campaign | Six `COMPONENT_OBSERVATION` shards; totals above; no missing cell |
| Formatting and crypto-package strict Clippy | Recorded commands exited zero in the retained checks excerpt |
| Original workspace strict Clippy | **FAIL, exit 101**; retained E0599 diagnostic for missing OpenSSL `private_key_from_seed` API |
| Provider-pinned supplemental verification | **PASS in the separate second supplement:** identical workspace/all-targets/all-features strict Clippy command, exit 0, no timeout; the original 3,600-second cap remains. Current OpenSSL 3.5.9 executable, two headers and two static libraries matched all five historical pins before and after; the original seven-key environment was selected explicitly. The first supplement exited 1 at the source guard before Clippy started because historical evidence paths had Git skip-worktree flags. Its original refusal remains in the archive. A separately recorded restoration checked every existing file against HEAD, restored only missing tracked bytes from local Git objects, cleared the hiding flags and passed the unchanged full source guard. The origin of the flags is not established. No source blob, checker, feature or timeout was changed. The original exit-101 compiler failure remains visible. |
| Parent #908 C5 | **FAIL 62/64**, failing `pnq2-42` and `cleanup-01`; **HOLD** remains |
| Read-only Root inventory audit | Checker reports `inventory_contract_satisfied=true`; selected 41-file register has no intersection with this change. `source_revision_bound=false` and HOLD remain; no map refresh is implied. |
| Archive transfer/verification | Complete byte-verified archive: 4,591,284 bytes, SHA256 `1f3f04c393e43c1c36fbb8b1569f810d9b8c9b31013d5389410ff2787a252a83`, 784 members. The full XZ/tar stream and every retained member were read back; archive integrity does not make the original failed checks phase pass., independent of the already completed native grid |

Component success does not repair C5, certify all workspace gates or authorize production. Keep supplemental provider receipts alongside the original failure. Archive/final-commit completion is separate from measurement completion.

The [strict reader](../../scripts/pon_w1_zero_paired_lazy_v1.py) distinguishes complete, invalid and incomplete records. Missing completion, partial bytes or unknown/nonzero exit leave unfinished costs unknown. Invalid/incomplete reports expose no comparative rates. Grammar, exact-type, roster, count and prefix checks do not authenticate clocks or execution.

## Security interpretation

For independent uniform 256-bit tickets and inclusive target T:

\[
p(T)=\frac{T+1}{2^{256}}.
\]

This is an explicit hypothesis, not a result proved by the finite grid. Under independent stationary trials, with one preparation P, miss cost c_f and success cost c_s:

\[
\mathbb E[C]=P+\frac{1-p}{p}c_f+c_s.
\]

With cost c per attempt and extra proof cost f on success, this becomes `P + c/p + f`. Caps, adaptive task choice, correlations, hardware, retained state and sharing require their full lifecycle model. Observed ratios are not universal expectations or lower bounds.

The [implementation comparison](../../docs/protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md) records generic preparation of 262,144 AB products plus 327,680 per challenge, versus 458,752 in original generation loops. The zero paired count is 152,832, including 33-bit-sum products. Counts are not equal-cost hardware operations, measured speedups or adversarial floors. An implemented legal strategy demonstrates an achievable cost; cheaper strategies may exist.

The [ESA 2026 PoUW paper](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2) states optimal adversarial hardness as a conjecture. Its asymptotic/multi-instance/streaming assumptions give no concrete lower bound for this 64-by-64, rank-eight relation. Ticket independence, resource attribution, task choice, maintenance economics and production difficulty remain open.

`cheapest_strategy_proven=false`; `production_activation=false`; `consensus_credit=0`. The independent numeric analysis also keeps `source_execution_authenticated=false`. These boundaries persist on successful component execution.

## Retained artifacts

This directory retains the original native observation and failures. The evidence commit changes documentation, evidence storage and the corresponding corpus pins; it does not rerun or relabel the native campaign.

| File | Role |
| --- | --- |
| [results.json](results.json) | Derived numerical report plus the recorded native, original-checks, restoration and supplemental outcomes |
| [excerpt.json](excerpt.json) | Read-only numeric manifest excerpt used for the independent arithmetic |
| [cost-results.md](cost-results.md) | Complete five-arm tables, fixed ratios and eight-cohort descriptive ranges |
| [native-evidence.parts.json](native-evidence.parts.json) | Native archive part/index metadata; Complete byte-verified archive: 4,591,284 bytes, SHA256 `1f3f04c393e43c1c36fbb8b1569f810d9b8c9b31013d5389410ff2787a252a83`, 784 members. The full XZ/tar stream and every retained member were read back; archive integrity does not make the original failed checks phase pass. |
| [archive-receipt.json](archive-receipt.json) | Actual archive/transfer verification receipt; Complete byte-verified archive: 4,591,284 bytes, SHA256 `1f3f04c393e43c1c36fbb8b1569f810d9b8c9b31013d5389410ff2787a252a83`, 784 members. The full XZ/tar stream and every retained member were read back; archive integrity does not make the original failed checks phase pass. |
| [local-development.tar.xz](local-development.tar.xz) | Earlier sparse-checkout development observations and failures, 17,036 bytes / SHA256 `13622446e72134ec3dbe49b4a57ab9cc5fb1ca6906d6072ee78e2ff660d6bcef`; never substituted for the complete-source native campaign |

The [delivery manifest](evidence-artifact-manifest.json) records each delivered file's size, SHA256 and Git blob. It excludes itself to avoid a hash cycle. The [ordered parts manifest](native-evidence.parts.json) binds all raw archive parts and their exact reassembly; each part is at most the unchanged 4 MiB reader cap. Retain source/build failures, incomplete observations, original Clippy failure and actual supplement. The known manifest hash refers to original bytes, not a reconstructed manifest.

Reproduce with the [runner](../../scripts/ci/run_w1_zero_paired_lazy_v1.py), project preflight, a complete clean committed checkout and new output directory. Preserve source/toolchain/ELF guards, 900-second build and 300-second shard caps, wait4 ownership and failures. A rerun has a new identity; it cannot rewrite this observation.
