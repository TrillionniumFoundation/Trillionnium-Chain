# M11 Evaluation profile, attested trust and integer merit

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Controlled real training and explicit evaluation producer; signatures still use the experimental attestor trust model.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M11.EvaluateFrozenModel

A candidate losing to the strongest calibration-locked control receives no improvement score; many snippets in one file are one statistical cluster. Freeze candidate/control/calibration before evaluation; calculate exact source-group sign test with multiplicity correction.

**Atomic/commit boundary:** Freeze candidate/control/calibration before evaluation; calculate exact source-group sign test with multiplicity correction.

### M11.AdmitEvaluation

Require one of three named development evaluators, not author, unique sender, expected plan and nonzero evidence. First2 valid attestations freeze minimum score; no extra votes change it. This admits attestation truth, not objectively recomputed ML correctness.

**Atomic/commit boundary:** Votes embedded in contribution state; no chainwork or validationmembership mutation.

## M11.StrongClusterControl

**Invariant:** A candidate losing to the strongest calibration-locked control receives no improvement score; many snippets in one file are one statistical cluster.

**Scope:** Controlled real training and explicit evaluation producer; signatures still use the experimental attestor trust model.

**Atomic boundary:** Freeze candidate/control/calibration before evaluation; calculate exact source-group sign test with multiplicity correction.

**Failure schedule:** Best single stronger than base; Candidate loses to best control; One hundred snippets from one source; Caller labels data future.

**Expected result:** A candidate losing to the strongest calibration-locked control receives no improvement score; many snippets in one file are one statistical cluster.

**Resource and retention rule:** At least20 clusters, four-comparison correction, integer/Fraction arithmetic; public reward eligibility stays false without owner-verified evidence.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_stronger_single_control_not_weak_base_is_selected`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_improving_over_base_but_losing_to_control_is_not_rewarded`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_snippets_from_one_file_do_not_become_independent_samples`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_positive_cluster_result_does_not_mint_future_acceptance`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Weak baselines, correlated samples, adaptive holdout reuse, poisoned evaluators and first-two arrival manipulation.

Fresh future windows, independent evaluators and a public dispute/aggregation profile are still required.

## Current source and verification

- [`formal/pon-nakamoto-v1/evaluation.py`](../../formal/pon-nakamoto-v1/evaluation.py).
- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M11` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Frozen evaluation and consent continuation

See [E3](../protocol/pon-nakamoto-v1/details/EVALUATION_BUNDLE.md) for exact bytes,
owner boundaries and failure schedules. No public export or future-window authority
is created by a frozen artifact. The following additional regressions are executable:

- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::StatisticalBoundaryTests.test_calibration_weights_source_groups_not_number_of_snippets`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::StatisticalBoundaryTests.test_positive_direction_majority_with_negative_mean_is_rejected`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::FrozenEvaluationTests.test_every_control_parameter_is_bound_before_inference`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::FrozenEvaluationTests.test_input_label_content_identity_and_group_substitution_reject`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::EvaluationWorkerTests.test_legacy_unbound_reference_cannot_authorize_evaluation`.

Actual producer/evaluator implementation: `formal/pon-nakamoto-v1/evaluation_bundle.py`;
normal controlled worker and three-attempt caller consume it rather than a parallel trainer.

Calibration claims are recomputed, not accepted merely because a producer can hash them:

- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::FrozenEvaluationTests.test_self_consistent_rehashed_calibration_score_still_requires_actual_replay`.
- `formal/pon-nakamoto-v1/test_evaluation_bundle.py::FrozenEvaluationTests.test_changed_calibration_data_cannot_be_substituted`.

## Native development continuation and remaining scope

Statement classes and the difference between retrospective gain, prospective benefit and bounded optimality are explicit in MODEL_EVALUATION. No optimality verifier or independent future-window authority has been admitted. Revision3 first-two evaluation order remains an explicit successor-policy obligation.

The current callable mappings remain in `config/pon/module-maturity-v1.json`.
Exact native entry, storage and work behavior is specified by N3 in NETWORK_CLIENT,
the native continuation in STATE_RECOVERY and the prepared-producer section in WORK_PROFILE.
No historical receipt is relabelled as executing this source.
