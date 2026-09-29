# M16 Bounded composition proposals and local intelligence

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Bounded local optimization and non-authoritative proposals only.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M16.TrainCompatibleCandidate

Use explicit full-batch softmax recipe,120stepslocal androuter, inverseclassfrequency, boundedquantization; selectroutertargets on calibration only. Emitnewimmutableartifact, never mutate activebundle.

**Atomic/commit boundary:** Training records owned by localproducer; chain receives only parameter/evidenceclaims.

### M16.CompareOrAbstain

The producer must retain all required deployable controls and reject overlapping training/calibration identities; a weaker composition need not be adopted. Train and calibrate before frozen evaluation; emit immutable candidate and reference records.

**Atomic/commit boundary:** Train and calibrate before frozen evaluation; emit immutable candidate and reference records.

## M16.NoForcedAdoption

**Invariant:** The producer must retain all required deployable controls and reject overlapping training/calibration identities; a weaker composition need not be adopted.

**Scope:** Bounded local optimization and non-authoritative proposals only.

**Atomic boundary:** Train and calibrate before frozen evaluation; emit immutable candidate and reference records.

**Failure schedule:** Omit a control; Overlap task identities; Composition loses to selected control.

**Expected result:** The producer must retain all required deployable controls and reject overlapping training/calibration identities; a weaker composition need not be adopted.

**Resource and retention rule:** Finite local optimization, disclosed training budget, no paid provider invocation.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_reference_cannot_silently_omit_a_control`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_duplicate_task_and_partition_overlap_reject`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Reward hacking, self-evaluation, adapting after seeing outcomes and absorbing existing Hepta owners.

Real chronological multi-generation learning and authenticated data withdrawals are not replaced by experimental splits.

## Current source and verification

- [`formal/pon-nakamoto-v1/evaluation.py`](../../formal/pon-nakamoto-v1/evaluation.py).
- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.
