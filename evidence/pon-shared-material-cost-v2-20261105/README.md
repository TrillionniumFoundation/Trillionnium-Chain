# Same-material W1: legal preparation, complete operator costs and retained failures

This continuation belongs to the sole Chain work plan and existing draft PR #688.
It uses the same model and request materials as the [first complete-operator experiment](../pon-shared-material-v1-20261105/README.md).
It finds a cheaper legal preparation on these materials, but **does not observe a net compute saving for the complete workload**.
No consensus relation, work target, proof wire, reward, adoption gate or original service budget changes.

## Frozen source and scope

- Measured source: `eeedfe33f9c7cd27a1855b865e7faa458047dcd1`, tree `5487be5fe9075298429c0a8cad60e33cf330f8bf`; every case observed a clean checkout.
- Native release binary: SHA256 `5e9ad2da5319b645dc6325d4466c4e822cf7ebc07ab116cdc04c18d3c14fcf7f`, 843,432 bytes, Rust 1.95.0, unchanged standard release profile.
- Original corpus source: `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`.
- Model domain hash: `16443887511f5ffbcdf611ce3ca6b6811bc699aad649961fce5a83c168534671`.
- Evaluation-bundle domain hash: `0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5`.
- Shared host: AMD EPYC 9V74, eight-CPU quota and 8 GiB memory cap. Contention was not controlled. The cost-reader audit also overlapped part of the campaign at 09:08:16.907–09:08:20.769 UTC; it is not the only possible noise source.

The [measurement contract](../../docs/development/specs/pon/SHARED_CELL_COST_V2.md) defines versioned observations and overlap rules.
[plan.json](plan.json) was written before execution. Its 31 cases are 24 paired observations (two targets, two transcript kernels, two preparation methods, three repetitions with alternating order), four actual verifier-fanout observations, two four-cycle reuse observations, and one declared search-exhaustion control.
[campaign.json](campaign.json) records **30 complete observations and one real exhaustion**, not 31 completed useful workloads.

The experiment remains one 257-coordinate integer model, five 64 by 64 W1 tasks and one frozen batch of 64 requests.
All 960 linear outputs, 64 routes, 192 logits and 64 predictions agree with ordinary integer execution.
The ordinary control caches base plus delta and evaluates only the router and selected expert.
Its 98,688 logical MACs occupy 7.5293% of 1,310,720 padded W1 positions.
Alternative arms, extra challenge cycles and additional verifiers earn no extra application-output credit.

## Cheaper preparation is real; complete useful work is still expensive

The explicit sparse preparation validates all canonical A/B words, indexes nonzero B entries and skips only zero products when preparing the fixed product and proof prefix.
It uses a full-field-safe u128 accumulator. The original dense default remains available.
Every challenge still computes the complete 512-tile transcript, original trace and ticket. No verification shortcut or special reward is introduced.

Within each target, all 12 paired observations have identical materials, seeds, nonce/challenge/trace/ticket streams, complete proof bytes and typed products.
Target 0 uses 14 attempts including nine misses; target 1 uses 58 including 53 misses.
The three repetitions repeat the same mathematical stream; they are timing observations, not independent model trials.

The following ratios first compare sparse to dense **within each repetition**, then take the median of the three ratios:

| Target / transcript kernel | Preparation CPU ratio | Whole native child CPU ratio | Whole native child wall ratio | Producer + native verification + copy CPU ratio |
|---|---:|---:|---:|---:|
| 0 / full-limb | 0.130884 | 0.896135 | 0.889977 | 0.854802 |
| 0 / transposed | 0.123082 | 0.767765 | 0.766552 | 0.726862 |
| 1 / full-limb | 0.142983 | 0.868798 | 0.836588 | 0.874762 |
| 1 / transposed | 0.118874 | 0.861321 | 0.794520 | 0.832407 |

On this batch, preparation CPU decreases about 85.7%–88.1% by the paired-median measure.
This legal optimization is equally available to an adversarial miner; it does not establish a higher minimum work cost or global cheapest legal work.

All batch timings cover the five W1 tasks for the same 64 requests. Native child values sum the five sequential child processes.
The next table instead reports each arm's three-observation median. Ratios in the last column are medians of each run's child-wall / its own ordinary-warm-wall ratio.
They are not a ratio of the separately displayed column medians.

| Target / kernel / preparation | Producer + native verification + copy CPU ms | Whole child CPU ms | Whole child wall ms | Ordinary warm wall median ms | Child wall / warm wall |
|---|---:|---:|---:|---:|---:|
| 0 / full-limb / dense | 8.538 | 28.247 | 31.210 | 0.083435 | 374.1x |
| 0 / full-limb / sparse | 9.440 | 32.785 | 36.775 | 0.083745 | 439.1x |
| 0 / transposed / dense | 11.531 | 37.419 | 41.011 | 0.084071 | 475.1x |
| 0 / transposed / sparse | 8.948 | 28.230 | 31.437 | 0.089146 | 352.6x |
| 1 / full-limb / dense | 26.452 | 49.039 | 55.158 | 0.084612 | 660.7x |
| 1 / full-limb / sparse | 23.212 | 42.626 | 46.145 | 0.083951 | 558.1x |
| 1 / transposed / dense | 33.549 | 55.702 | 63.056 | 0.083542 | 658.7x |
| 1 / transposed / sparse | 29.383 | 52.014 | 56.296 | 0.083560 | 662.0x |

The t0/full-limb arm medians and its paired-ratio median point in different directions; both are retained.
No claim is made that every sparse run is faster. In particular t1/full-limb/repetition-0 sparse takes 111.057 ms of child wall, 2.520589 times its paired dense run.
Across all 24 individual paired observations, child-wall / ordinary-warm-wall ranges from 208.8797x to 1322.8805x.

The child measurements include startup, diagnostic record construction/serialization and a second scalar reference verifier.
The smaller disjoint subtotal is producer (one preparation plus all searches, including misses) + all actual native full-verifier calls + typed copying.
Even this subtotal / ordinary warm **CPU** ranges from 58.2374x to 401.3280x across the 24 observations; the eight arm medians of that CPU ratio range from 101.1781x to 376.1653x.
This is a measured implementation subtotal, not a theoretical PoUW lower bound or full deployment cost.
Do not compare it to the earlier full-child wall ratios as if they were the same quantity.

## Full verifiers, retries and repeated outputs are charged

The N=3/8 runs perform real sequential full native verifier calls; the first call's legacy field is only an alias and is not charged twice.

| Target | N per proof | Actual native calls for five proofs | Total native verifier CPU ms |
|---|---:|---:|---:|
| 0 | 3 | 15 | 7.443573 |
| 0 | 8 | 40 | 19.926964 |
| 1 | 3 | 15 | 7.470413 |
| 1 | 8 | 40 | 19.642607 |

These calls share a process, hardware and administrator. They do not demonstrate that every independent network validator ran.

Four cycles produce 20 winning proofs and 20 full native verifications per target, but still only one distinct application batch.
Target 0 actually performs 42 attempts (22 misses); target 1 performs 624 (604 misses), with producer CPU 17.050383 and 243.189147 ms respectively.
The latter must not be replaced by `58 * 4`; its complete observed search stream is retained.

The declared one-attempt target-1 control exhausts at tile 0 with native exit 2. Tiles 1–4 never start.
Its finished native child costs 2.118000 ms CPU and 2.630469 ms wall, with 101,953 retained local pipe bytes and zero complete-output credit.
The containing consumer process tree costs 1.654702 s CPU and 1.705422 s wall, including source replay, baseline diagnostics and startup.
Those outer measurements contain the inner work; they must not be added to it.
The strict all-case reader therefore deliberately returns exit 2 / `incomplete_local_observations` while retaining all 31 cases.

## Cost coverage and remaining unknowns

| Cost item | What this campaign records | Boundary |
|---|---|---|
| Producer and unsuccessful nonces | Preparation, every complete search envelope and all observed attempts | Competing miners and abandoned remote work are unknown |
| Proof production | Winning proof materialization inside search; exact proof bytes and transcript identities | No isolated proof-materialization CPU timer; no new transparent-v2 receipt |
| Verification | Every actual requested native replay, scalar diagnostic and typed copy | N is a local measured count, not network population |
| Process and supervisor | Native children, current Python CPU, all-child CPU and inclusive outer consumer process tree | Nested scopes are not additive; wall is not summed across hypothetical parallel nodes |
| Transmission | Canonical inputs, proof/product bytes and actual local stdin/stdout/stderr bytes | These byte categories overlap; WAN bandwidth, latency and propagation are unknown |
| Repeated attempts and failure | Misses, four-cycle searches, actual exhausted process and unstarted tiles | Repeated identical useful output receives no new demand credit |
| Model/input handling | Read/validation/source-replay phase; reusable ordinary preprocessing; product consumption | Source replay is included; production device loading and distribution are not isolated |
| Stale blocks | Explicit hypothetical whole-batch retry scenarios | No measured stale-block rate or live-network stale experiment |
| Energy and full economic cost | Unmeasured fields remain null | No conversion from bytes, CPU or wall to money is assumed |

For one ordinary complete single-cycle observation, canonical material is 163,840 bytes, proofs 245,940 bytes and typed products 81,920 bytes.
Actual pipe counts include diagnostic encodings and repeated records; the three canonical counts are not extra traffic to add again.
Across the 31 sequential consumer invocations, the outer process-tree sum is 58.046083 s CPU and 58.474721 s wall.
This is the sum of the 31 observed consumer process-tree envelopes, including source replay and 100 baseline samples per case.
It excludes campaign-driver overhead, intercase gaps, security experiments, builds and reader audits; it is not one production inference latency.

[cost-scenarios.json](cost-scenarios.json) explicitly assumes 1/8/100 identical-cost verifiers and, where stated, a 10% independent whole-batch stale fraction.
The partial CPU expression is `(observed producer + N * first verifier + typed copy) / (1-s)`.
Misses are already inside producer and are not multiplied again separately.
Scenario output remains hypothetical, excludes model loading/consumer and other global costs, supplies no wall-time prediction and grants no qualification.
[cost-readback.json](cost-readback.json) keeps `full_system_cost=null`, `net_compute_benefit=null`, all unmeasured global coverage null and activation false.

## Same-material adversarial verification remains adverse in cost

Both targets were rerun on the exact same five materials and frozen native binary.
The attack mode is explicitly the original full-limb/dense native v1 mode, four cycles, one native verifier; it does not inherit sparse preparation or verifier fanout silently from a consumer manifest.

| Target | False-trace attempts | Candidate instances | Attack setup + search CPU ms | Raw native refusal CPU ms | Refusal / attacker CPU |
|---|---:|---:|---:|---:|---:|
| 0 | 78 | 40 | 1.386879 | 19.056003 | 13.740206x |
| 1 | 1,192 | 40 | 2.089282 | 19.538826 | 9.351933x |

All 80 candidate instances are rejected in the 360 recorded native/reference/cache calls.
Repeated calls are not 360 independent attack samples. All ten native processes complete without a missing clock or exhausted attack search.
For each target, each cache path has 20 calls. Warm means are 30.4388 / 27.2971 microseconds; after-owner-recreation means are 461.5835 / 482.2010 microseconds.
Cache setup/reset are separately retained. Recreation is volatile in-process owner loss, not durable service recovery.
The refusal/attacker ratio excludes diagnostics, serialization, supervisor and network costs; it is not a minimum-cost attacker bound or public-service qualification.

## Algebra audit and model adoption remain separate

The [algebra audit](reviews/legal-algebra-audit.md) reconstructs all five original winning-challenge traces from a prefix expansion over the exact field and checks every prefix word and final trace hash.
The ordinary generic expansion has more counted scalar products than the existing dense noise-plus-transcript path on these materials.
A narrow rank-one bias-tile expression is retained as an unimplemented, untimed candidate, not credited as a speedup.
The audit also retains the existing zero-material shortcuts as a reason not to infer irreducibility from dense masking.
Global cheapest legal work remains open.

There was no new training or model-selection trial. The [prior settlement](prior-model-settlement.json) for these exact model/bundle identities remains `not_adopted`, `model_reward=0`.
Numerical execution equality does not establish model improvement, an LLM forward pass, independent future evaluation, ordinary Hepta adoption or a funded effect.

## Validation, reproduction and publication boundary

On the exact frozen source: 138 crypto library tests (all 135 previous identities retained), nine native example tests, 12 consumer tests, 61 cost-reader tests (including 18 retained-observation controls run against the real-v2 fixture) with zero skips, 16 security-reader tests, two campaign-driver tests, 98 CI-contract tests and 35 source-integrity negative tests pass.
Strict default-feature Clippy for the changed crypto lib/tests/example, workspace formatting, locked offline Cargo graph, generated source inventory and repository/Markdown checks pass.
The source gate checks 487 pinned blobs and remains `HOLD_NO_GO`.
This is not a claim that every workspace package, runtime, feature combination or hosted workflow was executed.

The accounting controls bind baseline samples and outputs, parent clocks, each verifier, original stream fields, process aliases and advertised subtotals.
Earlier development failures and the initial cancelled debug build are retained in the archive; final passes do not erase them.
These checks establish record consistency under a caller-trusted binary. They do not authenticate a remote measurement author.

[summary.json](summary.json) preserves exact nanoseconds, ranges, paired ratios, scenario assumptions and all case indices.
[summarize.py](summarize.py) derives it from the strict readback, campaign and attack reports.
[validation.json](validation.json) and [source-files.json](source-files.json) bind the checks and measured implementation.
[REPRODUCE.md](REPRODUCE.md) gives the exact workflow.
[archive.json](archive.json) binds the separately delivered full raw archive, including every failed observation.

Concurrent History/readback and CI-roster work from `dda4cc47362065819e9591f11f713933e7a853bf` is preserved when this evidence is integrated.
The measurement identity above remains the actually executed source; an evidence/integration commit is not passed off as a new benchmark execution.
The original 0.25 CPU / 2 GiB / four-second / 16-hostile-work / depth-six service gate remains unchanged and unqualified.
No protected-main merge, deployment, reward, public-service qualification or production activation is performed.

[Publication validation](publication-validation.json) records the later composition with
`cf8c88acc026bd36a00aedb40e09aa380ddbc0eb`, preserving its Growth/runtime/research
changes and all seven relevant CI commands. The composed source gate checks 492
blobs and remains `HOLD_NO_GO`; the frozen measurement gate above checked 487.
The relocated archive passes every payload hash, all 31 strict readbacks and a
byte-identical standalone summary. The archive retains the earlier evidence
snapshot; later publication metadata does not change its measured costs.
