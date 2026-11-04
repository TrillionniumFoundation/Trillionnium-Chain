# Independent stored-weight verification supplement

This additive audit leaves the 2026-11-03 seed/final quantization package unchanged.
It closes a concrete verification gap: the original verifier did not require five
unique weight folds and did not recompute the retained fold-level perturbation,
clipping, disagreement, margin-summary and interaction measurements. This does not
imply that the original measurements were wrong. They pass the stronger checks.

No new model is fitted, no arm selected, and no efficacy or production claim is
added. The original 1/1,005 seed-treatment prediction disagreement and zero
final-rounding disagreements remain unchanged.

## Run

From the repository root, with Python and NumPy installed:

    PYTHONDONTWRITEBYTECODE=1 python evidence/seed-quantization-verifier-20261104/verify.py
    PYTHONDONTWRITEBYTECODE=1 python evidence/seed-quantization-verifier-20261104/test_mutations.py
    PYTHONDONTWRITEBYTECODE=1 python evidence/seed-quantization-verifier-20261104/check_read_boundary.py

The verifier reads the frozen package, original TRAIN rows and prior TRAIN-only
control report. It does not import the runner, trainer or evaluation modules. It
pins the original SHA256SUMS digest, requires its complete unique filename set,
checks all published package checksums and decoded result checksums, refuses
uncompressed shadow files, binds TRAIN/control/plan hashes, reconstructs the
original class-stratified whole-file folds, and requires exactly five distinct
weight folds and five ordered report folds.

All four stored-weight score arrays, predictions, margins, integer quantization,
seed identities, fold row/file counts, per-fold disagreement counts, clipping,
perturbation maxima and nonzero counts, interaction maxima, aggregate confusion,
correct counts and exact-rational file-macro accuracy are recomputed. L2 norms use
independent scalar math.fsum and sqrt, rather than the runner's NumPy norm; their
comparison allows relative tolerance 1e-13 and absolute tolerance 1e-15 for reduction
rounding. Other recomputed numerical values compare exactly. Integer dot products
are int64; checked input/weight bounds make overflow impossible at 257 coordinates.

Negative tests corrupt every reported fold measurement category in every fold,
all six weight arrays per fold, structural coverage, OOF values, aggregate metrics,
control predictions and package files. Mutations are in memory or temporary copies,
never in the frozen package. The original package is reverified afterward.
read-boundary.json records a runtime allowlist check of Python open events after
imports. This is evidence of application reads, not an OS syscall sandbox.

## Limits

This validates stored weights and measurements, not the training trajectory or
whether these weights were produced by the stated training steps. It does not
rerun training, certify an alternate NumPy/BLAS environment, adjudicate ownership
labels, or make development partitions statistically independent. Package hashes
provide integrity against retained commitments, not an external signature. The
historical environment and policy flags are recorded claims, not independently
measured history. This run used Python 3.12.14 / NumPy 2.3.5. This supplement does
not change the original collection's failed M04 probe coverage gate.
