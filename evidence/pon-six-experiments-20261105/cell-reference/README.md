# Complete reference search and honest cost readback — 2026-11-05

**Experiment 1: the bounded source-router relation was actually replayed; ordinary
Hepta Cell coverage remains HOLD. Experiment 2: all local reference attempts are
now retained and bound to delivery; a new best-native-miner or protocol cost
bound was not measured.** The prior fifteen-arm native economic observations
remain available and are summarized separately below.

The machine conclusions are [readback.json](readback.json). The
[complete report](complete/report.json), [independent search replay](complete/independent-search-replay.json),
[failed search](exhaustion/failure.json), and
[all-attempt failure replay](exhaustion/full-search-replay.json) contain actual
observations. [files.json](files.json) hashes the retained raw files. No activation,
model adoption, owner effect, service SLO or security-hardness gate is promoted.

## 1. Exact source and actual complete run

The run used working-tree source on base
`346b15148bf9b0b1319b047e37c6df0d92ccfc93`; that base commit alone is **not** the
identity of the changed implementation. The complete source/configuration/runtime
manifest is [program-identity.json](complete/program-identity.json), with relation
program digest:

`fcb23393e7cd0ced7f6c7d33f9e2e09f466506d6d4efd0972b3db9522ee83a2f`.

The driver and journal are separately pinned in the report and readback. Their
source bytes are captured at import and checked again before execution and before
the final report; changed disk bytes cannot silently relabel loaded diagnostics.
The final driver SHA-256 is
`bae56f23b99177e3c9660cc535d185b3cac253ef17e03a646984cf102b525ce4`, and the journal
SHA-256 is `ab2690602690aea851b95076c8dd1aee49b2b784b5992a6c60c84da8cc9de2fe`.

The original model's source is
`9fedf7ecbbe07177069c030592b4e03dcffebb81`. Its signed commit, 153 trees and 261
required source blobs were retrieved and checked against their exact Git object
hashes. This restored the actual source replay; no supplied feature rows or
successful source mock replaced it. Three missing quality fixture files were
also hydrated from their original Git blobs.

The final, newly executed observation used the reviewed ACK and first-hit binding
implementation, including the explicit success requirement that the delivered
witness matches the journal's first hits:

| Actual observation | Result |
| --- | ---: |
| Frozen source rows / distinct source inputs | 64 / 64 |
| Complete W1 tile transcripts | 5 |
| Started and completed search attempts | 11 |
| Winning / losing attempts | 5 / 6 |
| Attempts by tile | 2, 3, 2, 1, 3 |
| Witness bytes | 557,594 |
| Exact logits compared / matches | 192 / 192 |
| Routing decisions compared / matches | 64 / 64 |
| Fresh-process complete relation verification | Passed |
| Fresh-process replay of all attempts, including misses | Passed, 11 calculations |
| Delivered nonce, proof hash and trace equal measured first hit | Passed for all five tiles |

The full transcript verifier, independent scalar numeric calculation and actual
source extraction all ran. The unchanged transition is read-only: complete
before-state equals after-state. The model is the existing integer public-source
router. It has **no request/expert mask**, mutable neuronal state, ordinary Hepta
Encoder, enabled STOP/abstention, authenticated owner action or installed next
generation. Those missing product semantics keep the broader experiment open.

## 2. Failures, durability boundaries and delivery binding

The actual negative search froze 64 requests, five tiles and one attempt per
tile, using nonzero target `00...01`. Tile zero completed one genuine calculation
and missed the target. Its recorded CPU was 149,394,459 ns. The other four tiles
are **NOT_RUN**, the planned request denominator remains 64, and completed trial
outputs remain zero. The failed attempt was independently recalculated from the
same source-backed material. This is a bounded search exhaustion, not an invalid
input and not a successful block.

The new [journal](../../../formal/pon-nakamoto-v1/useful_cell_attempt_journal_v1.py)
records the frozen complete plan, each nonce start, each actual result/error and
the terminal status. The start is acknowledged before arithmetic. A crash after
a start leaves an unknown outcome; an absent completion does not become free or
unspent work. Preparation, source replay, diagnostics, verification and delivery
are outside the per-attempt arithmetic clock and remain separate scopes.

Two independently discovered accounting defects were reproduced and fixed:

1. **Another valid nonce is not the measured search.** Under maximal target,
   replacing the delivered tile-zero nonce 0 with an actual, valid nonce 1 proof
   still passes the original Cell/W1 relation. Rewriting the terminal witness
   hash used to leave the journal arithmetic check satisfied too. The final
   inspector now binds each delivered tile's nonce, proof SHA-256 and trace to
   the actual first hit. The genuine alternate proof is refused with
   `SEARCH_DELIVERED_FIRST_HIT`; W1 mathematical acceptance was not changed.
2. **Readable bytes are not an acknowledged terminal record.** A final line can
   be written and flushed before `fsync` fails. The driver now retains the last
   actually acknowledged byte count, entry count and endpoint. Both success and
   failure inspection use that prefix. The raw suffix is kept and hashed. The
   final-fsync fault retains all five completed arithmetic attempts but records
   zero completed producer batches and zero producer outputs, including nested
   counters in `failure.json`.

Creating the journal also fsyncs its containing directory. The claim remains a
**process-observed fsync acknowledgement**. The OS/filesystem is trusted; this is
not a power-loss experiment, acknowledgement of every ancestor directory,
external rollback anchor, independent custody or permission to retry an
uncertain operation. Experiment 6 owns real installation/effect reconciliation.

The [final test receipt](verification/cell-reference-reviewed-final-tests.json)
and [log](verification/cell-reference-reviewed-final-tests.log) record **92 passed,
zero failures/errors/skips**. A second agent independently ran five of the core
new negative controls successfully; those five are part of the 92 and are not
counted again. They include the genuine alternate valid nonce, final-fsync
failure, false ACK and diagnostic-source drift. These are functional controls,
not performance observations.

Earlier observations are preserved under `retained/`:

- `setup-source-unavailable` failed before source replay because historical Git
  objects had not been materialized. This is an environment setup failure,
  **not a product liveness failure**.
- `setup-quality-unavailable` reached complete proof and fresh-process relation
  verification, then refused missing calibration/evaluation files. It did not
  become a successful whole observation after those files were restored.
- `before-accounting-hardening-complete` and `before-accounting-hardening-exhaustion`
  preserve the earlier actual observations. Their reports are not relabeled as
  executions of the reviewed diagnostics.

One intermediate test log ended without a suite completion record despite an
executor exit-zero report. It is explicitly `UNCONFIRMED` in the readback and is
not counted as a passing suite. The separate final structured 92-test receipt
and complete log supply the current functional result.

## 3. Actual local cost, without an invented native comparison

The current positive run recorded **2,266,370,039 ns of Python process CPU** over
all eleven search calculations, including six misses. The instrumented prove
call consumed 2,500,995,047 ns CPU and 2,540,593,504 ns wall time. The full local
verifier took 1,255,441,801 ns wall, all-attempt replay 2,221,258,348 ns, and the
fresh-process relation check 4,907,118,370 ns. Freeze and retrospective quality
costs are also retained in the report. Nested clocks must not be added.

This was a shared host with concurrent work and no enforced CPU/RSS isolation.
The driver used its existing 600-second research deadline. These times do not
qualify the original four-second/16-worker Host service gate and cannot be
compared directly with earlier native timings. In particular, no native Cargo
miner executable was available for a new fifteen-arm census, and a slower
Python reference must not be presented as the best known honest implementation.
The current profile's cheapest-legal/miner advantage remains null.

The frozen original quality protocol was actually rerun too. The candidate's
marginal values against `mean_merge` remain negative on consumer, evaluation A
and evaluation B; the exact fractions are in [quality.json](complete/quality.json).
`model_reward=0`, independent future-window evidence is absent, and proving the
calculation did not turn this candidate into an adoptable improvement.

## 4. Prior fifteen-arm economics: explicit rho, cost scope and uncertainty

The pre-existing native experiment is retained, not replaced by the null current
native measurement. See its pinned
[README](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/evidence/pon-work-expensive-v1-20261105/README.md)
and [summary](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f9977c5d6d1b57880967ef36dcd1570010cbbe4f/evidence/pon-work-expensive-v1-20261105/summary.json).
[native-cost-readback.json](native-cost-readback.json) records the source Git blob
`be9d130ad312d51e93677e7c3625ca11ca362b61`, exact field pointers and integer costs.
Those observations executed source
`dd10f0aee7de54cbbf6e67c78bf85a5e1d59244d`, tree
`21eec0a14631db0de94cabad07a1d4c14bfe0388`, on
`pon-matmul-transcript-64-v1` with fifteen-arm native record v2.

For this **diagnostic comparison only**, define

\[
\rho_{\mathrm{cost,obs}} =
\frac{C_{\mathrm{calibration\ selected\ legal}}}
     {C_{\mathrm{dense\ reference}}}.
\]

Smaller rho means less observed producer CPU than that dense comparator. The
published `generic_to_selected_cpu_ratio` is its inverse. This is not a
protocol-security rho: dense is not the upgraded best known honest optimum,
and honest miners can use the selected legal optimization themselves.

Samples 0–1 select the algorithm with minimum aggregate producer CPU and fixed
tie order; samples 2–7 evaluate that frozen selection without choosing a new
winner. Each table cost covers the same material/challenge/target cohort and
six held-out samples of 64 completed attempts, including preparation, every
winner and miss, per-attempt cleanup and completed cache teardown. Verifier and
global material-preparation costs are separately reported, not silently included
in or removed from these denominators.

| Prior native case | Calibration-selected legal implementation | Selected / dense CPU, ns | Rho cost | Dense / selected speedup | Exact selection index |
| --- | --- | --- | ---: | ---: | ---: |
| Real material tile 2, target 1 | `lazy-full-limb-sparse` | 120,135,077 / 132,169,469 | 0.9089472622 | 1.1001738402 | 25 |
| Real material tile 1, target 1 | `lazy-full-limb-sparse` | 133,486,672 / 144,508,411 | 0.9237294291 | 1.0825680859 | 24 |
| All-zero synthetic material, target 0 | `blocked-zero` | 123,049,780 / 129,669,992 | 0.9489456898 | 1.0538010877 | 2 |
| Rank-one synthetic material, target 1 — adverse held-out result | `lazy-full-limb-sparse` | 135,294,098 / 128,008,276 | 1.0569168043 | 0.9461482644 | 13 |

Each index addresses `primary_census.calibration_selections[index]` in the pinned
summary; numerator is `evaluation_producer_cpu_ns`, denominator is
`generic_evaluation_producer_cpu_ns`. The first case is the largest observed
dense/selected saving among the 28 frozen calibration choices. The last case
retains a roughly 5.7% cost regression; held-out data did not replace its selected
arm. Synthetic zero/rank-one W1 operands are not automatically eligible source
inputs for the complete useful-Cell relation.

The original census planned 3,360 cells: 1,808 completed, 1,552 unsupported and
zero failed. Unsupported construction costs remain paid. It retains **115,712
completed attempts = 30,867 verified hit records + 84,845 misses**. Repeated arms,
target cohorts and tile results cannot be summed as distinct chain credits or
complete model outputs. Seven of ten real tile/target selections choose sparse;
these are useful best-known measured implementations in that finite set, not a
global cost minimum or a computational lower bound. Hardware/distribution
transfer, hidden preprocessing, adaptive task/challenge selection and confidence
or security upper bounds remain unqualified. `gamma` and live-chain accepted
work remain null in the original record as well.

**The invalid-input adversary is separate.** The original verifier observations
still show expensive rejection: new-challenge raw/negative-cache/arithmetic-fact
amplification 29.061× / 31.976× / 30.790×, and forced-eviction amplification
19.548× / 27.232× / 20.394×. Those denominators include actual preparation and
construction/search/clone costs, including misses. They are neither a new Node
stress test nor a service fairness bound. A legal sparse optimization does not
close this availability issue; the current reference journal did not measure
invalid-input rejection cost.

## 5. Reproduction

Use a new output directory; existing observations are never overwritten:

```sh
bash scripts/project-preflight.sh
PYTHONPATH=formal/pon-nakamoto-v1 python -m unittest -v \
  test_useful_cell_numeric_v1 test_useful_cell_attempt_journal_v1 \
  test_useful_cell_relation_v1
python formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py \
  --out /tmp/cell-reference-new-observation --batch-size 64
python formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py \
  --inspect-search /tmp/cell-reference-new-observation \
  --expected /tmp/cell-reference-new-observation/admission/expected.json \
  --search-plan /tmp/cell-reference-new-observation/admission/proof-search-plan.json \
  --search-acknowledgement /tmp/cell-reference-new-observation/admission/proof-search-acknowledgement.json
```

For the retained mathematical miss control, use another new directory,
`--max-attempts 1`, and target
`0000000000000000000000000000000000000000000000000000000000000001`.
The observed invocation exited 1 with `SEARCH_EXHAUSTED`; inspect its saved
journal with the same three separately retained context arguments. Do not turn
a failed command into an asserted success. Fresh timestamps/contracts yield a
different challenge stream, so a new run does not recreate old elapsed times or
promise the old hit sequence.

The three admission files here are explicitly **local reproduction fixtures**.
A real consumer must retain its own authenticated context, plan and endpoint.
Archived search inspection checks the old arithmetic and exact bytes; it does
not renew an expired deadline, re-authorize use, supply a live ACK or establish
independent administration. Runtime/source changes require new context; the
recorded program identity must not be rewritten to make an old run pass.
