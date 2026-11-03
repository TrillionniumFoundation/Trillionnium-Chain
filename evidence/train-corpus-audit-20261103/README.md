# Training-corpus audit and direct-test ablation

This continuation uses only original train.json and the historic source files
named by its rows. At source `6cdbf9551aae1754e489773bac29bc0598e20a9b`, all
1,005 row identities, snippet hashes, 257 features and inventory owner labels
reconstructed exactly. No owner-label corruption was found. No calibration,
evaluation A/B or consumer task data was loaded by the experiment.

## Mechanism audit

The corpus excludes tests.rs and /tests/ paths but includes inline directly
annotated Rust tests. M00's 41 direct-test rows yielded only 2 correct and 38
predicted M10, accounting for 38 of the 70 M00-to-M10 errors. Other M00 rows
were 43/83 correct. M10 direct-test rows were 171/186 correct. No misclassified
M00-to-M10 snippet was truncated at 4,096 characters. This is an association,
not proof that tests cause the generalization gap. Direct-attribute detection
is deliberately narrow, not a full Rust cfg/module parser.

## Frozen intervention and full result

The audit, ABLATION_PLAN.json and ablate.py were committed locally as 91e35679
before ablation execution. The candidate excludes only directly annotated test
rows from each fold's fit and seed pools. Baseline settings and five whole-file
folds remain fixed. Both use 8 seed steps and 120 pooled optimization steps;
removed rows mean fewer candidate sample updates, not equal measured FLOPs.
All 1,005 original score rows remain, including tests. Baseline was recomputed
and every prediction matched the earlier retained control.

Overall accuracy fell 647/1,005 to 640/1,005. Equal-file macro accuracy fell
84.6704% to 84.1751%; 16 files improved and 18 worsened, cluster gate false.
The direct-test subgroup fell 190/264 to 182/264. Other rows rose 457/741 to
458/741, insufficient to reinterpret the overall failure. M00 total accuracy
fell 45/124 to 44/124, despite direct-test M00 rising 2/41 to 6/41. No model
change is adopted and no public reward or efficacy claim follows.

The plan froze the full metrics and score population but did not explicitly
label primary versus secondary endpoints; it is not retrospectively amended
to claim stricter preregistration. All outcomes, including negative ones and
subgroup denominators, are retained. This one-pass intervention does not support
simply deleting inline tests as a remedy. Further work needs a new development
hypothesis; historical held-out data remains isolated.

## Reproduction and limits

Run audit.py against the available historic Git object, then ablate.py, capturing
stdout outside this evidence directory. The historical training input hash and
source bytes are bound in report.json. PLAN and script history precede execution
locally. Python 3.12.14 / NumPy 2.3.5 is not the repository's pinned qualification
environment. Cargo was unavailable; no Rust validation or independent future-data
acceptance is claimed. All changes are evidence and scripts, not runtime behavior.
