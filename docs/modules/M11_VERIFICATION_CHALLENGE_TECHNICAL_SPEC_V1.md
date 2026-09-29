# M11 Evaluation profile, attested trust and integer merit

Revision: invariant-driven revision2. The selected target remains `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [precise invariant/test registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Controlled real training and explicit evaluation producer; signatures still use the experimental attestor trust model.

This is an implementation boundary, not a claim of a complete native node or independent acceptance.

## PoN State machine

### M11.EvaluateFrozenModel

A candidate losing to the strongest calibration-locked control receives no improvement score; many snippets in one file are one statistical cluster. Freeze candidate/control/calibration before evaluation; calculate exact source-group sign test with multiplicity correction.

**Atomic/commit boundary:** Freeze candidate/control/calibration before evaluation; calculate exact source-group sign test with multiplicity correction.

### M11.AdmitEvaluation

Require one of three named development evaluators, not author, unique sender, expected plan and nonzero evidence. First2 valid attestations freeze minimum score; no extra votes change it. This admits attestation truth, not objectively recomputed ML correctness.

**Atomic/commit boundary:** Votes embedded in contribution state; no chainwork or validationmembership mutation.

## M11.StrongClusterControl

**Invariant:** A candidate losing to the strongest calibration-locked control receives no improvement score; many snippets in one file are one statistical cluster.

**Preconditions:** Exact installed revision2 context; current local owner and immutable task/evidence identities. Storage-only and controlled-attestation premises are explicitly labelled in their tests.

**Atomic boundary:** Freeze candidate/control/calibration before evaluation; calculate exact source-group sign test with multiplicity correction.

**Failure schedule:** Best single stronger than base; Candidate loses to best control; One hundred snippets from one source; Caller labels data future.

**Expected result:** A candidate losing to the strongest calibration-locked control receives no improvement score; many snippets in one file are one statistical cluster.

**Resource and retention rule:** At least20 clusters, four-comparison correction, integer/Fraction arithmetic; public reward eligibility stays false without owner-verified evidence.

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_stronger_single_control_not_weak_base_is_selected`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_improving_over_base_but_losing_to_control_is_not_rewarded`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_snippets_from_one_file_do_not_become_independent_samples`

`formal/pon-nakamoto-v1/test_evaluation.py::ModelGateTests.test_positive_cluster_result_does_not_mint_future_acceptance`

These selectors identify actual test functions, not a class-name count. A binding checker cannot label a test passed; the separate exact-source command receipt must show execution and outcome.

## Module-specific threat and residual work

Weak baselines, correlated samples, adaptive holdout reuse, poisoned evaluators and first-two arrival manipulation.

Fresh future windows, independent evaluators and a public dispute/aggregation profile are still required.

No assertion of independent operators, physical durability, ordinary Hepta execution or future model efficacy follows from local fixtures.

## Current source and verification

- [`formal/pon-nakamoto-v1/evaluation.py`](../../formal/pon-nakamoto-v1/evaluation.py).
- [`formal/pon-nakamoto-v1/experiments/model_loop.py`](../../formal/pon-nakamoto-v1/experiments/model_loop.py).

Run the relevant native package and exact Python test selectors through the protocol CI lane. Preserve source hashes, failures, backend, filesystem and process/host scope. Historical evidence is never relabelled as current.
