# Useful-Cell relation: source and reproducibility record

Date: 2026-11-05, America/New_York. Continue the existing integration candidate
PR #688, `fix/chain-six-axis-performance-20261103`.

**Result:** the new `pon-useful-cell-int257-v1` reference relation was actually
executed on 64 frozen public-source tasks. Five complete W1 transcripts passed
verification, the independent scalar output agreed exactly, and a fresh process
verified the saved statement against separately supplied context. The original
quality/settlement replay still returned **`not_adopted`, model reward 0**.
This is a bounded research result, not ordinary Hepta, a succinct proof,
work-security qualification or production activation.

## Exact source and controls

Tested implementation commit:
[`6541befe89742ea09d928864d0e6581213182382`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/6541befe89742ea09d928864d0e6581213182382).
It is retained in the integration history, including concurrent native and evidence updates
merged afterward. Those other native changes are not qualified by this record. [manifest.json](manifest.json) records the exact bytes
of 28 implementation/configuration/test/document files, the 18-file executed
source closure, input hashes, runtime versions, commands, observations and limits.

| Executed control | Result |
| --- | --- |
| New complete-relation rejection tests | 47 passed |
| New numeric and decision counterexamples | 20 passed |
| Existing complete-operator regressions | 9 passed |
| Combined operator/numeric/relation run on the implementation commit | 76 passed, no skipped tests |
| CI execution-contract controls on the implementation commit | 99 passed |
| Project boundary / 26-package inventory | Passed |
| Embedded native source inventory consistency | Passed |
| Changed documentation relative targets | 274 checked, no missing targets |

The CI command sequence now requires both new control suites. Its negative
controls refuse removing, duplicating, moving, skipping or swallowing those
commands. Exact source pins were refreshed for the changed CI sources; existing
native commands and acceptance budgets were retained. GitHub Actions outcomes
are not preclaimed. Cargo tests, formatting and Clippy were not executed in this
environment, where Rust/Cargo is absent. This complete-relation change adds no
Rust implementation; concurrently merged native work retains its own gates.

The [composition checks](composition.json) confirm that all 18 executed
reference source files and the full program/parameter identity are unchanged
through the latest recorded integration `76cfac184a0e7d1002b9ce28aa1997341074c88a`.
Both recorded compositions pass all 99 CI controls. The later integration retains
concurrent grouped/native research, both required CI command sets and the exact
combined source pins. It records each changed documentation/CI registration file
against the original 28-file snapshot; none is an executed dependency of this
reference verifier. Concurrent grouped/native work is not qualified by these
reference tests and retains its own native acceptance obligations.

## Actual complete-operator observation

The experiment uses source commit
`9fedf7ecbbe07177069c030592b4e03dcffebb81` and the existing model artifact
`d6ac3f24a43045dda6af862344918688b5fbb047599d423e27c567cf670ccfc2`.
No new training data, trained Encoder or independent administration was supplied.

| Observation | Actual result |
| --- | --- |
| Frozen consumer window | Offset 0, 64 tasks |
| Feature coverage | 257 coordinates, tile widths 64/64/64/64/1 |
| Complete operator outputs checked | 15 × 64 = 960 integers |
| Final logits | 192/192 exact; mean and maximum absolute error 0 |
| Routing | 64/64 agreement with the independent integer reference |
| STOP / abstention | Both explicitly disabled; false for every row |
| Full W1 proofs | Five verified, including transcript and product |
| Frozen search target | `7f` followed by 31 `ff` bytes |
| Actual search attempts by tile | 1, 2, 1, 1, 1 |
| Raw PNW1 bytes | 245,940 |
| Canonical witness JSON bytes | 557,594 |
| Separate process verification | Passed |

The contract ID for this observation is
`97c4727ab52082c4cd09444319179c3972ced3f6f3a23bb834d5db1d375226c1`.
The pinned program digest is
`5cc3a91b8d85b0249d38cc479c13b76c6261224faaed5573e27c96149d7a6919`.
The manifest retains the actual deadline and verifier clock observations.

The ordinary integer reference and the W1-backed consumer use the same frozen
model semantics. Their exact agreement is not a BF16 conversion result. A
disabled STOP bit is not evidence that a STOP-enabled model preserves behavior.
Reference Python timings are recorded separately from prior native performance
observations and do not establish an acceleration or an adversarial minimum cost.

## Quality remains a separate, negative result

The existing evaluation bundle was replayed with its frozen calibration-selected
`mean_merge` comparator. Values below are equal-source-group accuracy, not
unweighted per-snippet accuracy. Exact rational values are in the manifest.

| Frozen partition | Rows / source groups | Candidate | Strong reference | Difference, percentage points | Original cluster gate |
| --- | --- | --- | --- | --- | --- |
| consumer | 213 / 27 | 79.096547% | 79.356804% | -0.260257 | Failed |
| evaluation_a | 170 / 25 | 73.932638% | 74.111058% | -0.178420 | Failed |
| evaluation_b | 184 / 27 | 77.178209% | 79.026888% | -1.848679 | Failed |

These three evaluations replay the original ordinary integer inference protocol;
only the specified 64-task consumer window received the new five-proof relation
experiment. They are retrospective source partitions, not untouched future data,
OOD or old-task retention tests. Calibration here locks the comparator; it does
not measure confidence calibration. The original `settle_model.py` was also
actually executed and preserved `not_adopted` / zero reward.

## Reproduction

Use the tested commit or verify all listed source hashes. The existing tracked
model/evaluation directory and frozen Git source must be locally available;
source replay refuses missing material and does not substitute synthetic data.

```bash
bash scripts/project-preflight.sh
PYTHONPATH=formal/pon-nakamoto-v1 python3 -m unittest -v \
  test_useful_cell_numeric_v1 test_useful_cell_relation_v1 \
  test_shared_cell_operator_v1
python3 scripts/ci/test_ci_contract.py
python3 formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py \
  --out /tmp/trnm-useful-cell-v1-new-run --batch-size 64
python3 formal/pon-nakamoto-v1/experiments/settle_model.py \
  --input evidence/pon-native-node-v1/model-current/model \
  --out /tmp/trnm-original-adoption-new-run \
  --bundle-hash 485d1ddac3f10b859599297ede15c5703517952d3f507cdc3efea7f14214429e
```

Every output directory must be new. A fresh experiment freezes a fresh absolute
deadline, so its contract, challenges, nonces and proof hashes can differ. Do not
extend an expired frozen request or accept it under the present clock. The driver
also supplies an explicit `--verify-dir` / `--expected` mode; an actual consumer
must retain and authenticate expected context through its own owner.

Only source, tests and this compact reproducibility record were added for this
increment. Generated witness/data/log bytes were not uploaded; their hashes
identify the observed execution, and the commands regenerate new observations.
The [full relation specification](../../docs/development/specs/pon/USEFUL_CELL_RELATION_V1.md)
defines canonical bytes, source replay, state, numeric rules, domain separation,
fixed-verifier identity and the remaining owner/proof/quality qualification gates.

The manifest preserves the initially discovered scalar-interface failure, stale
loaded-code/profile identity counterexamples and the initial CI-control failure.
Their corrections and rejection tests do not erase the separate negative
quality result or prior native cost observations.
