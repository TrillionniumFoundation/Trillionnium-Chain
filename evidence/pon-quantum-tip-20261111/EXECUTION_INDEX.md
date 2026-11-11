# Fixed-source execution index: quantum / DAA continuation

The implementation candidate is
[`a0cf721c0a3fd5bc034e010119d2b09d148de8ec`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a0cf721c0a3fd5bc034e010119d2b09d148de8ec),
tree `0fee4598d69db92beea2845c6d939f059f2d14a3`, reviewed in
[Draft PR #893](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/893).

This evidence branch records later-arriving execution output without moving
that implementation candidate. An evidence commit is not an executed candidate.
Every result below retains its own source identity.

| Executed source | Recorded result | Original record |
| --- | --- | --- |
| `2582a6d15a14d3929d3238d844e710f5a291b422` | 150 model/qualification tests and six selected native tests passed; 72 complete horizons and 72 replays passed. CI source, formatting, lifetime-source and other failed observations remain preserved. | [Source3 raw logs and summaries](actions-2582a6d15a14/README.md) |
| `67f78a87da0e6797c0262e69e95f367bc549be38` | 388 model/lifetime/CI-control tests passed, 72 horizons and 72 replays passed, and all six selected native library tests plus whole-workspace formatting passed. Both lanes verified their complete source before and after. | [Source4 complete focused record](actions-67f78a87da0e/README.md) |

The later W1 current survey is documented in
[its own fixture preparation record](../pon-w1-lifetime-current-20261111-qdaa/README.md).
That source data does not substitute for actual execution of its nineteen-test
recomputation and refusal suite.

The final candidate has its own
[focused run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942301962),
[required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942309045)
and [W1 closure run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942309148).
This revision of the index does not claim their results. Later observations
must name their exact tested commit and tree.

## Limits retained

- The old desktop original-production/new-regression process was last observed
  running. Its terminal negative-baseline result remains UNKNOWN.
- Native current-clock regressions do not exhaust concurrent clock rollback
  during W1, owner races, long-chain costs, or hostile-load liveness.
- The [QROM fixed-source review](qrom-fixed-source-review.md) is a source review.
  The original frozen-source refusal remains; no contract or limit is loosened.
- Earlier from-zero and fresh-service failures remain separate observations;
  their child failure evidence has not been unpacked in this review.
- All quantum/consensus/lifetime/production qualifications remain false or
  unknown. Passing finite experiments, source checks and regression tests does
  not establish an all-legal-algorithm W1 bound or CP/CG/CQ.
