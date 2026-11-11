# Execution index: quantum mining, difficulty and current-clock admission

## Current candidate and observed result

Implementation candidate: [`a0cf721c0a3fd5bc034e010119d2b09d148de8ec`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a0cf721c0a3fd5bc034e010119d2b09d148de8ec), tree `0fee4598d69db92beea2845c6d939f059f2d14a3`, under [Draft PR #893](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/893).

The final candidate completed both focused Actions lanes and independent desktop execution:

| Observation on the exact final candidate | Actual result | Preserved record |
| --- | --- | --- |
| Focused Actions: Python and qualification | 431 tests passed in ten suites; explicit unproved-qualification refusal returned exit 3 | [Both original CI job logs and summary](actions-a0cf721c0a3f/README.md) |
| Focused Actions: paired policy campaign | 72 full horizons, 36 pairs, all 72 seeded replays; 1844 measurement requests | [Run 42942301962](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942301962) |
| Focused Actions: native library and format | Six tests passed, neither required regression missing, no failed or ignored tests; whole-workspace formatting passed | [Native raw log](actions-a0cf721c0a3f/native-current-clock.log) |
| Independent desktop Python execution | The same ten suites passed all 431 tests; all 72 observations and replays completed; qualification refused as required | [199-member original-evidence ZIP, readable receipts and driver](desktop-a0cf721c/python/README.md) |
| Independent desktop native execution | Six tests passed, both required names present; whole-workspace formatting passed | [Original native observations](local-native-a0cf721c/README.md) |
| Independent trace reconstruction | 72 trace hashes, 55,658 rows and 4,383 created blocks checked; all final observer ancestries and weighted credit reconstructed | [Analysis and complete machine-readable results](final-a0cf721c-independent-analysis.md) |

Every final execution lane checked the full tracked candidate before and after:
**27,930 entries / 2,555,806,765 bytes**, with the exact commit and tree.
The desktop source snapshots are byte-identical. Test execution is evidenced
by separate command outputs and real exits, not by source checks alone.
Re-executing the same seeded panel validates replay; it does not create new
independent statistical samples.

This evidence branch records results arriving after candidate publication.
**The implementation head remains `a0cf721c`.** An evidence-only descendant
does not itself receive an executed-candidate or production-qualification claim.

## What the paired observations actually establish

For all 36 pairs, the difference in quantum-mined blocks on the final observer
chain is zero, and independently reconstructed **adopted required-work credit
also differs by exactly zero**. Required work was recomputed from every created
block's target using `floor(2^256/(T+1))`, and parent/height/chainwork recurrence
was checked before following the final ancestry.

| Domain / policy | Quantum created blocks | Quantum adopted blocks | Quantum adopted credit | Stale quantum proofs completed |
| --- | ---: | ---: | ---: | ---: |
| Abstract / discard-restart | 30 | 28 | 3,627,068 | 0 |
| Abstract / measure-on-tip | 279 | 28 | 3,627,068 | 249 |
| Finite N=4096 / discard-restart | 0 | 0 | 0 | 0 |
| Finite N=4096 / measure-on-tip | 12 | 0 | 0 | 12 |

The measure arm creates **261 more blocks and completes 261 more stale proofs**
in aggregate. This is a count comparison across differing event histories,
not a coupling identifying individual counterfactual extra blocks.

The quantum **share** of adopted credit rises in 6 pairs, falls in 4, and is
unchanged in 26 because total observer credit can change. Equal quantum credit
therefore does not mean equal relative share, monetary reward, or profit.

Modeled proof wall time rises by about 262.49 seconds and candidate-check
processor time by about 230.05 seconds across the panel. These distinct units
are not combined into a physical cost. Measurement requests are not completed
physical measurements.

The model has uniform receiver delay and retains the current chain on equal
work, making the ordinary reactive same-parent race effectively gamma zero.
The policies share initial seeds but can consume randomness and schedule
events differently. The finite domain is a 4096-ticket stress model, not the
native 64-bit nonce space. Three seeds per configuration provide no tail or
confidence guarantee. This honest-tip panel is not an adversarial timestamp/DAA
attack campaign. [All scope and per-case details](final-a0cf721c-independent-analysis.md)
remain attached to the observations.

## Recovered original native red-to-green record

The old desktop process actually completed at 2026-11-11 01:06:20 UTC; its
terminal evidence became readable after transport recovery. Earlier UNKNOWN
statements are preserved as historical information states and are superseded
for current knowledge by the [recovered original record](recovered-native-precommit-e4abb172/README.md).

With old production bytes from `e4abb172` and the new regression, the first
fresh-request case had already returned `TIME_DEFERRED`, but its W1
`work_started` counter was 1 instead of 0. The test failed with exit 101
after compilation: **0 passed / 1 failed**. This demonstrates late refusal
after W1 started. It did not demonstrate invalid activation, and the failing
first loop prevented a separate duplicate-case negative baseline.

After the three-file repair, the new test passed both fresh and duplicate
cases, the independent retained postcommit guard passed, and the six-test
public Growth selection passed. This historical working-tree observation is
not full committed-source validation. The two production blobs match the final
candidate; the historical test file differs only by one formatter line wrap.
The final candidate's separate full-source CI and desktop results are listed
above.

## Earlier fixed-source observations remain preserved

| Executed source | Recorded result | Original record |
| --- | --- | --- |
| `2582a6d15a14d3929d3238d844e710f5a291b422` | 150 model/qualification tests, 72 horizons/replays and six selected native tests passed. CI pin, formatting and lifetime-source failures remain preserved. | [Source3 raw records](actions-2582a6d15a14/README.md) |
| `67f78a87da0e6797c0262e69e95f367bc549be38` | 388 tests, 72 horizons/replays, six native tests and whole-workspace formatting passed; both lanes verified complete source before and after. | [Source4 raw records](actions-67f78a87da0e/README.md) |

The [current W1 lifetime survey](../pon-w1-lifetime-current-20261111-qdaa/README.md)
was originally a prepared source fixture. Its retained nineteen-test suite now
actually recomputed it at `a0cf721c` in both the focused CI lane and desktop
execution. The historical fixture description remains a preparation record.

## Unresolved boundaries and qualification

- The [QROM fixed-source review](qrom-fixed-source-review.md) documents two
  inherited production-file differences in a frozen sixteen-file roster.
  The contract, reader, size bounds, and original failed observations are
  preserved; source drift is not converted into oracle-cost qualification.
- The [required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942309045)
  remained pending at this final read. The current
  [QROM implementation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942309112) and
  [W1 closure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42942309148) jobs were queued.
  The focused pass does not imply complete repository CI success.
- Earlier from-zero and fresh-service controller failures remain separate
  observations; their child failure evidence has not been unpacked here.
- The portable log-name repair passed its current nineteen storage controls,
  five discovery controls and 180 CI mutation controls. This alone is not
  a result for the full next-architecture native acceptance workflow.
- Native regressions do not directly inject wall-clock rollback during
  unlocked W1, and do not exhaust owner races, retained-history scale costs,
  or hostile-load liveness.
- All **18 environment inputs remain unknown** and all **13 proof obligations
  remain open**. CP/CG/CQ, business liveness, and lifetime failure bounds remain
  null. The actual `--require-qualified` result is exit 3 with
  `REFUSED_UNPROVED_JOINT_CONSENSUS`; a successful `--check` is only
  contract consistency.

Status remains **HOLD / NO-GO**. No all-legal-algorithm quantum work lower bound,
native W1 marked-set reduction, production delay/resource model, or
confirmation failure probability is established by these observations.
