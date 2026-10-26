# W1 compact winner production: results and remaining obligations

## 1. Outcome and scope

This stage demonstrates an actual compact producer that removes avoidable diagnostic output from online W1 mining while retaining complete winning packets for the original native receiver. All 13 preregistered jobs completed. The four matched comparisons produced **1.411765–2.542373 times as many complete, subsequently accepted winning candidates within the same allocated miner CPU budget** as the freshly rebuilt late-deferred comparator. These are local observations on one nonexclusive x86 host, using two seeds and nested nonce prefixes. They establish neither a universal algorithmic advantage nor production throughput. [Analysis](analysis.json), [job records](jobs.json), and [independent reviews](independent-reviews.json) retain the exact observations.

The stage also completes two explicitly conditional mathematical obligations, C33 and C34, and an ordinary mining clock correction, C37. The native production and evidence obligations are C35 and C36. **The original project obligations retain their original standards: O01–O04 and O06 remain OPEN; O05 and O07 remain conditional and unadopted. Production activation is false.** Pure matrix PoN remains the selected research direction. No result turns an instrumented implementation's observed CPU consumption into a minimum cost enforceable on an arbitrary miner. [Blocker ledger](blockers.json)

## 2. Frozen source and evidence identity

The measured commit is **`4b18f6bdf226553514b07caf9259360d44631a06`**, tree **`8739627f52d68fc8dcff84282838edb940bfe81c`**. A later report publication does not replace that measured source. The original [13-job plan](../../formal/pon-nakamoto-v1/experiments/w1_compact_miner_plan_v1.json) fixed algorithms, seeds, budgets, caps, ordering and controls before collection. Both actual executables were built afresh from this source using Rust 1.95.0, locked offline release dependencies and two build jobs.

| Evidence | SHA-256 |
|---|---|
| Registered plan | `893c2be3ede87d951c94fea93079b25cc6a9dead173f85b0be9e6a48ff423c3b` |
| Compact executable | `238ab912fe410ecd001a2c3a82c5272e1e2ee8b72acecbae0f20557c019d713f` |
| Late-deferred executable | `2524fe86e0bde3be4f515397dd8a1e260ab4b37090b33d2bd62b59e8a0ffea43` |
| Campaign manifest | `fcb7ec43037f32ebc775801eaccd6df5614924ab947662d4784e29d3a1dd2679` |
| Complete derived readback | `a028fe3d660c959b4e58b356fb4f0089f95072dc99f1e572909827c9b72f0897` |
| Analysis | `db84a3a38e103dc1c8b6710daf609079dc22c9318ad535407f0e420953126bbd` |
| Frozen local validation | `21e2d05a3dea351b41c1605bf2404e57796b53223f5a1208816a009e6c6d9004` |

The strict reader checked **425 transitive source, helper and configuration files**, totaling 7,196,104 bytes, against exact frozen Git blobs before and after replay. Their source-set digest is `851f5205853d4ce9f4089e6f8127d1792d6d8c735a5429ade1fc076e3959e564`. Source, tree, plan, manifest and both executable identities require external pins; the analyzer additionally requires the readback's external SHA before decoding it. This is source-bound evidence, not hardware, interpreter, clock or execution attestation. [Summary](summary.json), [artifact index](artifact-index.json), [delivery manifest](delivery.json)

## 3. What the miner actually does

The [compact contract](../../docs/protocol/pon-nakamoto-v1/details/W1_COMPACT_MINER_RESEARCH_V1.md) preserves the comparator's original maintenance relation, real Node setup, prepared integer-paired kernel, parent, task, nonce schedule, trace and ticket functions. Both arms pay for preparation, including the existing cached matrix product. The prior deferred producer already assembled full research proofs only for winners; this experiment does not claim to have newly removed its cached matrix multiplication or losing-proof assembly.

The new path removes per-attempt diagnostic JSON and hexadecimal trace output. On a hit it assembles the complete original proof and uses the original `Packet::encode()` format. Each winning packet is **49,508 bytes**: a 318-byte header, the zero-transaction count encoding, and the 49,188-byte PNW1 proof. Misses retain counters and a continuously updated trace commitment rather than full original diagnostic records. The commitment's online hashing cost is charged and remains removable instrumentation, not a protocol work requirement.

Phases are **setup → miner → receiver → audit**. Setup has its own CPU allowance P; research cannot begin unless setup actually completes within P. Miner allowance B is one process-CPU budget, polled before each attempt. Work includes challenge construction, failed attempts, proof construction, packet encoding, actual stdout writes and flushes, bookkeeping and seal production. Atomic stages may overshoot; their full cost and outcome remain recorded. A safety-cap stop is explicitly censored.

A winning packet becomes available only after its entire original output has been flushed. Availability by B determines the budget numerator. After the complete miner seal, the original native receiver decodes those emitted bytes and performs admission, in order. Its results never feed back into generation. Late complete winners remain present and may be accepted, but receive zero B credit. The audit then independently reconstructs every fixed nonce, including misses, and checks the commitment and original winning bytes; it supplies no new credit. Python scalar replay verifies the relation and evidence, without reexecuting native Node state transitions. No research candidate is activated, and no canonical growth or mature reward is claimed.

Both arms ran with CPU affinity 0 on the same visible AMD EPYC 9V74 x86_64 host. Nine logical CPUs were exposed; that observation does not describe the entire physical host. The CPU was not exclusive. The launch declared tmpfs storage for temporary databases, builds and raw output before collection. No energy, ARM, GPU, memory-bandwidth or WAN measurement was obtained. Verified lossless gzip runs after each child exits and preserves original lengths and hashes; compression does not alter the miner's measured output path. [Launch context](launch-context.json), [visible hardware](visible-hardware.json)

## 4. All 13 registered outcomes

Main jobs use P = 1 second and cap = 4,096. Budgets and seed order below are the preregistered execution order. “B winners” means full output available by B and subsequently accepted; “accepted” includes late winners. All eight main jobs completed setup and stopped on actual budget exhaustion, without cap censoring. [Job records](jobs.json)

| # | Arm / control | Seed | B | Attempts | B winners | Accepted | Outcome |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | Late-deferred | 7101 | 128 ms | 178 | 86 | 86 | Budget stop |
| 2 | Compact | 7101 | 128 ms | 340 | 162 | 163 | Budget stop; 1 late winner |
| 3 | Compact | 7102 | 128 ms | 313 | 168 | 168 | Budget stop |
| 4 | Late-deferred | 7102 | 128 ms | 217 | 119 | 120 | Budget stop; 1 late winner |
| 5 | Compact | 7101 | 512 ms | 1,245 | 600 | 600 | Budget stop |
| 6 | Late-deferred | 7101 | 512 ms | 500 | 236 | 236 | Budget stop |
| 7 | Late-deferred | 7102 | 512 ms | 747 | 394 | 395 | Budget stop; 1 late winner |
| 8 | Compact | 7102 | 512 ms | 1,408 | 738 | 738 | Budget stop |
| 9 | Compact, P = 0 | 7103 | 128 ms | 0 | 0 | 0 | Setup incomplete |
| 10 | Compact, P = 1 ms | 7103 | 128 ms | 0 | 0 | 0 | Setup incomplete |
| 11 | Compact, B = 0 | 7103 | 0 | 0 | 0 | 0 | No attempt |
| 12 | Compact, tight B | 7103 | 100 µs | 1 | 0 | 1 | Late winner, zero B credit |
| 13 | Compact, cap = 2 | 7103 | 512 ms | 2 | 1 | 1 | Explicitly censored |

The tight setup control consumed 5,915,376 ns through an atomic setup stage, exceeded P and did not begin research. The tight miner control consumed 382,238 ns, retained its complete late packet and excluded it from B credit. The cap control consumed only 633,091 ns in the miner phase; it is not evidence of exhausting 512 ms. Zero budgets still incur administrative phase costs while authorizing zero research attempts.

## 5. Four matched comparisons

Each pair has identical paid setup identity, resource parameters and every shared semantic opportunity and hit prefix. Shared prefixes contain respectively 178, 217, 500 and 747 attempts in the table's order. Longer runs under the same seed reuse those deterministic prefixes, so the four comparisons are not four independent populations. There is one observation per arm and no confidence interval or universal maximum-advantage claim. No comparison to an older-source campaign is used. [Analysis](analysis.json)

| Seed / B | B winners, compact / late | Allocated-B rate ratio | Actual-miner rate ratio | Actual setup+miner rate ratio | All-local-raw-byte ratio |
|---|---:|---:|---:|---:|---:|
| 7101 / 128 ms | 162 / 86 | 1.883721 | 1.903087 | 1.925795 | 0.450542 |
| 7102 / 128 ms | 168 / 119 | 1.411765 | 1.414559 | 1.408917 | 0.381758 |
| 7101 / 512 ms | 600 / 236 | 2.542373 | 2.634872 | 2.636970 | 0.593231 |
| 7102 / 512 ms | 738 / 394 | 1.873096 | 1.873491 | 1.875447 | 0.488996 |

Every ratio is compact divided by late-deferred. Equal allocated B makes the first ratio equal the winner-count ratio. The next columns divide those same numerators by measured miner CPU, then measured setup-plus-miner CPU. Receiver and audit costs are deliberately separate. The byte ratio covers **all local research output, including posthoc audit**, not network bandwidth or compressed archive size. All four winner ratios exceed one in this campaign; their magnitude remains sensitive to the measured implementation and environment.

The observed [development target](../../config/pon/devnet-v1.json) is `7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`, or T = 2^255 − 1. **Only under an ideal uniform ticket assumption** does p = (T+1)/2^256 equal 1/2. This was not a production-difficulty campaign. Different target difficulty changes how often winning-packet assembly and output occur. These ratios cannot establish production throughput, consensus capacity or a physical mining-cost floor.

## 6. Proof records, attempts and identities

Three totals describe different objects and must not be added as independent work. [Supplemental accounting](supplemental-accounting.json)

| Evidence class | Count |
|---|---:|
| Compact original research packets | 1,671 |
| Compact original setup packets | 7 |
| Late original research proofs | 837 |
| Late original setup proofs | 4 |
| Late posthoc research proofs | 805 |
| Late posthoc setup proof records | 4 |
| **Full retained proof records replayed** | **3,328** |

Thus 3,328 comprises **2,519 original records plus 809 posthoc records**. The four posthoc setup records repeat setup winners; they are not misses. Separately, compact replay recomputed **3,316 deterministic nonces**, comprising 3,309 research attempts and seven setup attempts. Its 1,638 research misses have no retained original full-proof records. Recomputed winners overlap original packets; these counts are not additive proof populations.

Across both arms and controls, **4,951 research attempt occurrences** comprise 3,309 compact and 1,642 late attempts. There are 2,508 accepted research winner occurrences, of which 2,504 are B-eligible, and nine late attempts including four late winners. Main jobs contribute 2,503 B winners; the censored control contributes one.

Cross-job deduplication yields **2,655 distinct semantic research opportunities and 1,339 distinct B-credited candidate identities/native block IDs**. Repeated compact semantic identities agree on header, proof, trace, ticket, challenge and block identity. Every possible late hit, including late winners, is already contained in the compact runs' actual B-credited union. This derives the union without inventing missing failure timings or granting reconstructed credit. Setup is excluded. Even these deduplicated observations do not establish global reward consumption, maturity or universal fanout across arbitrary executions.

## 7. CPU scopes and residuals

The cumulative phase observations, across all 13 jobs, are:

| Scope | CPU nanoseconds |
|---|---:|
| Setup | 136,417,935 |
| Miner | 2,583,585,432 |
| Receiver | 9,220,749,347 |
| Audit | 7,075,537,097 |
| Phase sum | 19,016,289,811 |
| Direct native origin-to-endpoint total | 19,016,375,046 |
| Whole waited child command | 19,068,900,000 |

The direct endpoint exceeds the phase sum by **85,235 ns**, retained rather than silently discarded. Whole-waited minus native CPU is **52,524,954 ns** in total, ranging from 2,774,840 to 6,086,935 ns per job. It includes work outside the recorded native interval, final serialization and remaining drops. Signed residuals are not clamped. GNU time's printed CPU has its separately registered 20 ms allowance; waited endpoints use 2,000 ns. [Supplemental accounting](supplemental-accounting.json), [analysis](analysis.json)

Main-job miner overshoot spans **192,868–18,936,642 ns**. The maximum belongs to seed 7101/B512 late-deferred and remains in its actual-miner denominator. Compact post-stop seal work spans 3,024–24,236 ns. Availability-to-accounting bookkeeping is also charged. No estimate subtracts observer costs from an old run to fabricate a faster miner. Receiver and audit CPU are substantial, but neither their sum nor the miner-only rates measure canonical chain growth, TPS or remote delivery.

## 8. Conditional theory: C33 and C34

The final reporting basis is the **v2 theory-review receipt** retained in [independent reviews](independent-reviews.json), together with the [literal ticket composition proof](../../docs/protocol/pon-nakamoto-v1/details/W1_TICKET_COMPOSITION_V3.md) and [native DAA resource interface](../../docs/protocol/pon-nakamoto-v1/details/W1_NATIVE_DAA_RESOURCE_V2.md). These close bounded proof obligations, not the original actual-system blockers.

**C33** uses a fixed IV, an empty initial table and independent per-message-block ideal permutations accessible in both directions. Full preprocessing exposure is captured. Literal W1 encoding and complete pre-answer c/d/t references bind canonical material before the relevant lottery response. Every sealed t/d is registered before any terminal audit query; one immutable copied snapshot prevents audit-created paths from entering miner capacity. An enlarged analysis filtration reveals the disjoint noise family only to the mathematical observer, never as free miner information. This establishes predictable canonical-valid marking without assuming a separately independent ticket oracle.

The experiment fixes caps **Q_P** for preprocessing exposure, **Q_A** for subsequent online calls, **V** for all terminal checker calls, **G** for sealed openings including failures, and **R** for complete references including guesses, repeats and audit references. All workers, tasks and forks share those allowances. Public or outsourced exposure included in Q_P is not thereby shown physically paid by this miner. Audit calls V affect depletion and failure bounds, not captured miner path work. Set C_all = Q_P+Q_A+V; the stated nontrivial regime has 1 ≤ C_all ≤ M = 2^256. The extractor's R ≤ 3C_all+2G+R_explicit allowance requires every term capped beforehand.

After k_b pairs have been exposed under a ticket-final key, its fresh conditional hit probability lies between max(0,(T+1−k_b)/(M−k_b)) and min(1,(T+1)/(M−k_b)). It is not generally the exact uniform value. Shared-key depletion gives p̄_T = min(1,(T+1)/(M−C_all+1)). The ordinary-history Join error is bounded by δ = min(1,2C_all(C_all+R)/(M−C_all+1)); it is added after comparison-process analysis, never conditioned away while retaining a uniform lottery claim.

Outside Join, each different canonical challenge requires a disjoint captured **2,049-entry trace path**, with at most one native candidate identity per valid lottery input. D0 counts retired old canonical challenges, including winners and misses; K0 counts their known winning identities. **D0 and K0 may be random.** Their comparison-process shadow counts are measurable in the enlarged past and agree with the covered old bank outside Join; this does not assert ordinary-past measurability of arbitrary later-opened claims. Prepared but unseen outcomes remain in Q_P, not a second free winner bank.

For predeclared fixed integers d,k, with 0 ≤ 2049d ≤ Q_P and k ≥ 1, let n_d = floor((Q_P−2049d+Q_A)/2049). The fixed-target result is:

\[
\Pr[W\ge K_0+k\;\land\;D_0\ge d]
\le \Pr[\operatorname{Binomial}(n_d,\bar p_T)\ge k]+\delta.
\]

A favorable realized D0 or query total cannot replace those fixed thresholds after observing outcomes. Arbitrary classical adaptive queries, batching, inverse queries and free joint matrix algorithms are already allowed inside this capped model; batch independence is not assumed.

**C34** integrates native weight w(T)=floor(M/(T+1)) using the upper conditional mean **ρ = M/(M−C_all+1)**. For predeclared global opportunity bound n and deterministic weighted old-bank bound w0, D>w0 gives the candidate-forest bound min(1,ρn/(D−w0)+δ+ε_ext). With a valid deterministic increment cap Wmax, the corresponding exponential bound uses βρ = 1+ρ(z^Wmax−1)/Wmax and βρ^n/z^(D−w0), for z>1, plus the same external failures. K0 alone cannot replace weighted w0, and forks do not receive fresh budgets. Total forest work upper-bounds any constituent branch; siblings cannot be summed into a single heaviest branch.

Actual SHA instantiation, arbitrary uncaptured or non-uniform advice, seeded tables, physical-resource conversion, honest visible service and settlement remain unproved. In particular, actual-SHA coupling is not silently assigned ε_ext=0. An ideal primitive query count does not establish a matrix multiplication, energy or useful-training floor.

## 9. Ordinary clock correction and Hepta boundary

**C37** corrects the ordinary wall-clock miner's precheck to use the original admission timestamp predicate on at most **11 projected ancestors**. It uses observed time, preserves non-median errors, rejects unsupported native-growth state explicitly and leaves original target preparation/admission responsible for the deeper DAA window. It does not manufacture future time from a parent timestamp. Five exact-source clock regressions and the separate mature 70-block/window fixture passed. This is a local correctness correction, not an O03 settlement or honest-growth proof. [Validation](validation.json), [mining implementation](../../trillionnium/crates/trnm-pon-node/src/mining.rs), [store implementation](../../trillionnium/crates/trnm-pon-node/src/store.rs)

Hepta source **`de133b601e133917cbe1ae03efb3a2ffc06dcd4a`** contains the owner-selected fixed genesis material. The inspected source/evidence still lacks the distinct ordinary **initial-only host constructor** and a real measured base forward/ordinary parent. Initial parent creation must not require a previously improved child. This was source review, not a new model execution or adoption. Real task lineage, independent quality and poisoning evaluation, later evaluated-child CURRENT/FinalUse authority, cross-node complete-Cell loading, adoption and rollback remain O06 obligations. [Hepta source review](hepta-source.json)

## 10. Validation, retained failures and closure boundary

Frozen local validation passed **270 Python test executions**: 192 direct controls plus 78 canonical-plan controls. Selected Rust scopes passed **249 tests**, with **two original explicitly ignored cost-observation tests** retained; there were 251 selected cases including those ignores. The pass count comprises 179 crypto/protocol, 48 across eight examples, 12 selected Node library tests and ten selected integration tests. Whole-workspace/all-target/all-feature strict release Clippy passed. These are not full-workspace runtime tests: Node library filters intentionally excluded other modules. Hosted CI was not consulted, and preliminary successful executions were not double-counted. [Validation](validation.json)

All 13 formal native jobs, complete scalar replay and the externally pinned analyzer passed, with no resampling. Retained history includes pre-freeze analyzer pin/type corrections, the material seal/snapshot correction, an unmaterialized reader checkout that failed before replay, shared-overlay capacity incidents and an earlier automatically rejected expanded timestamp research request that was stopped rather than executed. The launch's tmpfs choice preceded sampling. Source gates and acceptance thresholds were not weakened. [Failure history](failure-history.json)

The ledger closes **C33** within its captured ideal model, **C34** within its conditional weighted-forest interface, **C35** for actual compact production and complete nonce audit, **C36** for this frozen matched comparison and complete evidence replay, and **C37** for ordinary timestamp correctness. Internal independent-agent review is not an independent hardware/operator audit.

O01 still requires an actual resource-to-valid-opportunity reduction. O02 still requires justified bounds beyond the finite captured model and observed implementations. O03 still requires resource/lottery coupling, honest visibility, propagation and all-fork settlement. O04 lacks independent hardware and physical measurements. O05 remains an unadopted mixed-work option requiring composable binding and cost accounting; O07 remains an unadopted proof-backend option requiring actual statement, identity and amortization analysis. O06 retains the Hepta obligations above. No original closure standard was relaxed. The complete numerical result, preserved evidence and outstanding conditions are available through [summary](summary.json), [blockers](blockers.json), [artifact index](artifact-index.json) and [delivery](delivery.json).
