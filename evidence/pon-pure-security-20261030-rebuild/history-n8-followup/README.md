# Existing N8 History candidate: bounded successes and unmet depletion coverage

This is a 2026-10-30 UTC readback of actual historical source
`540d72356a921da31dde1113537382e5c0f0c4fd`, not a new native execution or a
production change. It resolves the failure attribution left open by the adjacent
[strict baseline diagnostic](../history-baseline/README.md).

The existing explicit `history-account-graph-resource-fence-v1` (N8) candidate
did **not** fail its pure raw History baseline through a 30-second timeout,
incorrect State or erased graph notifications. Across the retained three runs
and nine phases, all **27 depth-six confirmations** completed in their original
30-second windows. The original independent reader accepted all nine complete
verifier traces, and each original phase reported full receiver/client State
equality.

The complete campaign still **failed**. All six hostile phases lacked the
required observed paid-credit depletion, including depletion overlapping a
signed round. That unmet stress-coverage requirement remains a failure; timely
confirmation at the delivered load does not qualify service after depletion.

## Provenance and independent limits

The source tree is `37abfb254dd598226651cd0da42a78aa0560e23e`.
The original [workflow run 40932471986](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471986)
used job `123654218705`, artifact `12922584378`, and the native selector:

```text
separate_process_pure_history_raw_graph_fence_campaign
```

The original archive has 76,626,593 bytes and SHA-256
`87f5f7b1486b66d963c41228557f80f000d68295791012bb318321f9c1d07f50`,
verified against retrieved GitHub artifact metadata. The full archive is not
copied here. The original source-bound release test executable was
`123c08a3390569da3cd05441a4357f8dc601552413759cace7f77192e20efa64`;
its before/after hashes and per-verifier binary bindings agree.

[provenance.json](provenance.json) binds 31 original entries and eleven original
source files. Deterministic gzip preserves all three complete aggregate reports,
including all nine phases, failure records, stdout/stderr, source/binary identity,
hardware/resource observations, results, and the original phase/verifier
readbacks. Native binaries are not duplicated.

[reproduce_readback.py](reproduce_readback.py) rechecks all compressed/raw hashes,
source/binary/report identity, timing sums, exact graph counters, sampled
depletion predicates and reported acceptance conditions. The actual successful
readback process and its output are retained in
[readback-process.json](readback-process.json) and [readback.json](readback.json).

```sh
python evidence/pon-pure-security-20261030-rebuild/history-n8-followup/reproduce_readback.py
```

This reproducer does not newly execute the native verifier, inspect every
original request/response file, replay application execution or independently
reverify State equality. It checks the unchanged aggregate reports and their
original complete-reader results. These CI observations are not independently
authenticated host proofs. Finite samples do not prove continuous absence of
transient depletion.

## All three runs and all nine phases

Every phase retains the original quarter-CPU History verifier, original
30-second window, 21 actual imports, three signed rounds and depth-six
confirmation. The three modes retain 0/24/24 attacker processes. Receiver and
attack actors remain in the original separate outer experimental parent.

| Run | Mode | Confirmation times from phase start, seconds | Original phase verdict |
| --- | --- | --- | --- |
| 1 | baseline | 9.577915622; 17.771617073; 26.180082007 | PASS |
| 1 | from-zero | 10.458395298; 18.842221888; 27.464329723 | FAIL: required depletion unobserved |
| 1 | late-product | 9.851976580; 18.343953326; 26.745982205 | FAIL: required depletion unobserved |
| 2 | baseline | 8.093903568; 15.003254019; 22.002793236 | PASS |
| 2 | from-zero | 9.563832804; 17.673286291; 26.158316875 | FAIL: required depletion unobserved |
| 2 | late-product | 9.466223071; 17.760168692; 26.161575489 | FAIL: required depletion unobserved |
| 3 | baseline | 8.087030339; 14.880504652; 22.079731984 | PASS |
| 3 | from-zero | 9.642702306; 17.933192060; 26.846951111 | FAIL: required depletion unobserved |
| 3 | late-product | 9.459558418; 17.758275522; 26.274131072 | FAIL: required depletion unobserved |

All nine phases retain full receiver/client State equality, actual clean verifier
close/exit, complete observations, available CPU accounting, zero verifier
errors and 21 accepted blocks. In each hostile phase all 24 actors were ready
and completed without forced kill or attempt-cap exhaustion. Every signed round
overlapped attack calls and actual rejected hostile work. No hostile call had an
`ok` status. The successful original economics condition also remains true.

The largest final confirmation time is 27.464329723 seconds. This is a retained
finite observation, not a worst-case bound for arbitrary offered load.

## Exact failed predicate

The original native phase predicate is in
[public_v3_multiprocess.rs](../../../trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs),
and the independently recomputed observation predicate is in
[read_pure_history_raw_campaign_v1.py](../../../scripts/ci/read_pure_history_raw_campaign_v1.py).
For a sample to count as genuine depletion, all of these original conditions
must hold:

```text
remaining_paid_credit_ns < 100_000_000
paid_cpu_debit_ns > 1_900_000_000
clock_failures == 0
accounting_unavailable == false
```

The hostile phase also requires such depletion to overlap at least one signed
round. All six hostile phases had **zero** qualifying samples and all round
depletion flags were false. Their sampled minimum remaining paid credit ranged
from **963,126,582 ns to 1,694,436,962 ns**, above the required 100,000,000 ns
threshold. The sample populations were 591 or 592 per hostile phase; the full
sample records are retained in the original aggregate reports.

The other reported common and hostile conditions pass. Consequently all three
native test invocations exit 101 with `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED` in the
workflow result. This is neither an infrastructure interruption nor a claim
that the observed honest confirmations failed. No criterion is removed or
relabelled to make the original campaign green.

## The actual N8 graph path is active

Each of the nine phases has these identical structural counters:

| Actual counter | Value per phase |
| --- | ---: |
| Graph entries / exits | 249 / 249 |
| Graph node CPU/cancel checkpoints | 370,383 |
| Completed graph node bodies | 370,383 |
| Full graph resource checks | 47,076 |
| Instrumented inner kernel checks, including other boundaries | 77,178 |
| Maximum node-body window | 8 |
| Imports / clean closes | 21 / 21 |
| Import failures, graph aborts, scope failures, unfinished scopes | 0 |
| Kernel failures, unavailable kernel CPU observations, binding failures | 0 |

The recorded inner kernel-check CPU spans 3.283658855 to 3.625153647 seconds
per phase; total verifier-call process CPU spans 4.901764281 to 5.800153166
seconds. These scopes are nested, and their times must not be added. Full graph
resource-check count includes entry/final/exit fences in addition to the
every-eight-node schedule; the table is not a timing speedup ratio.

The typed path is preserved in the original source:

1. [ingress.rs](../../../trillionnium/crates/trnm-pon-node/src/ingress.rs)
   selects `GraphProgress` for the explicit ordinary N8 import.
2. `admit_history_packet_with_native_control` passes its native progress object;
   the post-W1 admission bridge dispatches `NativeProgressPoint` through
   `TypedNativeProgress`. Parent-state, publication and post-write checks retain
   the typed graph notifications.
3. The final-page N8 branch calls `activate_observed_with_native_progress`
   directly with the same typed controller. The strict branch separately uses
   its original `FnMut` compatibility adapter.
4. [history_graph_resource_v1.rs](../../../trillionnium/crates/trnm-pon-node/src/ingress/history_graph_resource_v1.rs)
   keeps CPU/cancel attempts on every graph node and complete current SQL/graph
   validation. Fresh kernel reads are bounded by eight node bodies, with full
   checks at graph entry, node zero, final relation, exit, ordinary boundaries,
   real commits and settlement.

Neither the source review nor these actual counters support the hypothesis that
the N8 campaign accidentally erased all typed graph events and repeated the
strict kernel check at every graph node. No wiring fix is made here.

## Interpretation for the pending security work

This is an existing named resource-policy candidate with finite positive service
evidence. Its source calls it a different observation schedule, with no
wall-clock revocation guarantee and no claim to detect a resource change reverted
between observations. The fixed physical ceiling and every actual graph relation
remain; the original strict policy remains separately available and separately
failing in the diagnostic.

The measured transport/work composition is `pure-history-raw-v1`. The adjacent
45-second failure uses the distinct newer Pure PoN fixed-Host pressure
composition. Shared source and account scale do not make these interchangeable
experiments. This readback makes no causal speedup-factor claim and does not
substitute N8 results for the strict gate or for a new Pure PoN composition.

Further work can test an explicitly bound N8 composition on the newer admission
path while preserving the old failure and all original scope/limits. The missing
depletion experiment needs its own actual offered-load and cost evidence. The
present nine finite phases establish neither service under exhausted paid credit
nor arbitrary-identity fairness, WAN behavior, PoN hardness or production release.
