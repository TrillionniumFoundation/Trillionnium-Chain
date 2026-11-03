# Train-only quantization diagnostic

A distinct development experiment, not another frozen evaluation replay or a repeat
of the historical file-balanced weighting experiment. The plan and script were
committed locally as `88f89ad7` before the first execution. Both are retained
unchanged. Only the original public `train.json` was loaded as experimental data;
calibration, evaluation A/B and consumer files were not opened by this experiment.
The original training data is not a new independent or future test set.

## Result

Five fixed class-stratified, whole-file folds covered 1,005 rows from 150 files.
Every seed and pooled fit excluded its scored fold. Same learned float64 weights
versus the original scale-1024 quantization yielded identical predictions on all
1,005 out-of-fold rows: zero disagreements and zero clipped weights. Both obtained
647/1,005 correct, 84.6704% file-macro accuracy. Fold-specific values, all predictions,
file errors and class confusion are retained in `report.json`.

Quantization is not the cause of these observed pooled-model errors. This does
not establish that quantization is harmless for every model or input. There were
no cross-label exactly identical feature vectors; absence of exact duplicates
does not rule out hash collisions, information loss or feature ambiguity.

The class confusion exposes a development weakness: M00 has 45/124 correct, with
70 predicted as M10; M04 has 132/220 correct; M10 has 470/661 correct. File sizes
range from 1 to 94 snippets, so sample accuracy and equal-file accuracy differ.
No parameter change, new model adoption, public reward, independent evaluator
acceptance or production activation follows from these results. No historical
held-out results were used for selecting settings or tuning.

## Reproduction and limits

Run `python evidence/train-only-quantization-20261103/run.py` and capture stdout
outside this evidence directory, then compare with `report.json`. Run `verify.py`
to verify the frozen plan/input hashes and retained identity/prediction accounting.
The prior report remains immutable. Python 3.12.14 / NumPy 2.3.5 is the available
host, not the pinned NumPy 1.26.4 qualification environment. Cargo is unavailable;
this does not claim Rust validation. No expensive training or external compute
was launched. Future improvement requires a separately frozen development plan
and untouched independent data before any efficacy claim.
