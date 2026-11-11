# Final-source quantum tip-policy observations: independent trace review

Status: **HOLD — conditional simulator observations only.**

Source: [a0cf721c0a3fd5bc034e010119d2b09d148de8ec](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a0cf721c0a3fd5bc034e010119d2b09d148de8ec), tree `0fee4598d69db92beea2845c6d939f059f2d14a3`.

The complete machine-readable review, all 72 reconstructed observations, all 36 comparisons, exact work-share fractions, per-case resource counters, trace hashes, and the actual read-only reconstruction program are in [final-a0cf721c-independent-analysis.json](final-a0cf721c-independent-analysis.json).

## What was actually checked

The original completed Python batch reports 431 passing tests, 72 complete 600-second simulations, 36 parameter pairs, and 72 successful seeded replays. Its qualification request correctly refused with exit 3. Source snapshots before and after are identical: 27,930 tracked entries and 2,555,806,765 bytes. Those are source and execution observations, not a consensus proof.

This independent review separately verified the frozen report and manifest hashes, all 72 compressed trace hashes, 55,658 trace rows, and 4,383 created blocks. For each created block, its recorded work equals `floor(2^256/(target+1))`; parent order, height, and cumulative chainwork recur exactly. Following each final observer tip back to the shared prefix reproduces the report's added-block and added-work totals. The read-only analysis process `1a1c87a62fd-135c4-97` finished successfully with exit 0, complete output, and no stderr. It did not rerun simulations or change the original report, traces, or source.

The panel spans two domain models, processors 1 and 4, uniform propagation delays 0 / 0.5 / 5 seconds, seeds 4101 / 4102 / 4103, and two policies. Only the tip policy differs within each pair.

## Adopted work, not just block counts

Quantum adopted work means the sum of `required_work` for quantum-mined blocks on the observer's **final** ancestry after the initial prefix. It excludes stale/off-chain blocks and the initial prefix, and is not a monetary reward.

| Domain and policy | Cases | Quantum blocks created | Quantum blocks on final observer chain | Quantum adopted work | Stale quantum proofs completed | All-miner adopted added work |
|---|---:|---:|---:|---:|---:|---:|
| Abstract, discard/restart | 18 | 30 | 28 | 3,627,068 | 0 | 116,034,550 |
| Abstract, measure on tip | 18 | 279 | 28 | 3,627,068 | 249 | 116,243,829 |
| Finite 4096, discard/restart | 18 | 0 | 0 | 0 | 0 | 113,362,728 |
| Finite 4096, measure on tip | 18 | 12 | 0 | 0 | 12 | 113,362,728 |

**Every one of the 36 pairs has exactly zero difference in quantum adopted block count and quantum adopted work.** This work result was reconstructed from the final chains; it was not inferred from equal block counts.

The created-block count rises by 261 and the stale-completed-proof count also rises by 261. Their differences agree in every pair. This is a comparison of observed counts; different event histories do not supply a counterfactual matching of individual blocks.

The quantum **fraction** of adopted work is not unchanged in every pair. The all-miner denominator changes: the fraction rises in 6 pairs, falls in 4, and is equal in 26. Across the abstract cases, the ratio of summed quantum work to summed observer work is about 3.125852% for discard/restart and 3.120224% for measure on tip. These ratios of descriptive sums are not an expected return or a statistical estimate of an optimal strategy.

## Resources in their declared model units

| Domain and policy | Completed logical iterations, all processors | Search wall seconds | Proof wall seconds | Candidate-check processor seconds | Proofs started / completed / censored |
|---|---:|---:|---:|---:|---|
| Abstract, discard/restart | 177,935 | 10,770 | 30 | 3.75 | 30 / 30 / 0 |
| Abstract, measure on tip | 173,191 | 10,519.51 | 280.49 | 116.30 | 282 / 279 / 3 |
| Finite 4096, discard/restart | 178,100 | 10,800 | 0 | 3.75 | 0 / 0 / 0 |
| Finite 4096, measure on tip | 178,138 | 10,788 | 12 | 121.25 | 12 / 12 / 0 |

Across the entire panel, measure on tip makes 1,844 measurement requests. Proof wall time increases by about 262.49 seconds and candidate-check processor time by about 230.05 seconds. Candidate-check processor time increases in every pair. Completed logical iterations decrease by 4,706 in aggregate, with 13 positive and 23 negative pair deltas; partial rounds still consume charged wall time. Search plus proof wall time remains 600 seconds per case. Different units in this table must not be combined into one physical cost.

The opt-in policy separately records 19.04 measurement wall seconds / 47.51 measurement processor-seconds. The legacy discard schema does not expose separate measurement columns; its measurement cost remains included in search time. Missing counters do not mean zero cost. Declared clocks and these arithmetic counts are not measurements of W1, quantum hardware, energy, or financial profit.

The finite stress panel creates 964 domains under discard/restart (936 empty) and 960 under measure on tip (932 empty), about 97.1% empty in each arm. Its 4096-ticket domain is not the native 64-bit nonce space.

## Boundaries of the conclusion

The model uses uniform propagation, strict greater-work adoption, and first/current-tip retention on equal work. A same-parent competitor measured after receipt of an honest block faces gamma = 0 in this panel. Heterogeneous routing and priority delivery are outside the experiment.

The same initial seed does not imply identical realized arrival times or histories: policies alter random-number consumption and event schedules. These are only three seeds for each configuration, not a tail bound or confidence guarantee. The panel uses honest-tip behavior and does not establish security against timestamp/DAA attacks or all quantum strategies. It does not prove the absence of an advantage under a different network or resource model.

No CP/CG/CQ, quantum work lower bound, native W1 marked-set relation, or whole-chain quantum security qualification is established. All such qualification flags remain false and release status remains HOLD.

## Evidence identity

- Original `paired/report.json`: 641,396 bytes; SHA256 `2e70fd95fe3fb9763d311241fe979089ff5644a23b77859413705b09a3c77efc`.
- Original `execution-manifest.json`: SHA256 `63e96b22d1329515e423cf701c2b421bff7da2e4ce41f8973780fe80f9a979fc`.
- Original `source-before.json` and `source-after.json`: SHA256 `bbf4c3be432d3440eff4ee91c279c9e134d2bc1b0d4e16521926f5b12490f9bb`.
- Original evidence ZIP: 1,243,895 bytes; SHA256 `299afbddd6f390d2f19c5346c746d5dfe5d4e39856d4650ffbdd8568ae494acb`.
- Independent read-only trace reconstruction stdout: 53,171 bytes; SHA256 `9bb9ddb0aac10c25fe0630a242586fa809703283f6ff6cf3120efe26c02b69e8`.

The JSON retains exact integer credits and rational share changes. Table times are rounded for readability; raw observed floating-point values remain available.
