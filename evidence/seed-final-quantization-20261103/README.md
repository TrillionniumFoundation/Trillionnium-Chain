# Fixed seed/final-weight quantization diagnostic

This paired 2x2 computation closes the shared-seed limitation in the earlier
quantization diagnostic. The plan and runner were committed locally as b07f8059d
before execution. Local history records that order; it is not an externally
timestamped preregistration. No thresholds or parameters were selected afterward.

## Observed result

All 1,005 original TRAIN rows across 150 files retain their five whole-file folds.
Each fold uses one eight-step floating-point seed and two 120-step pooled fits,
initialized by that seed or its scale-1024 quantized/dequantized version. Each fit
is scored before and after original final-weight quantization.

- Primary endpoint, seed treatment before final rounding: 1/1,005 prediction differs.
- Seed treatment after final rounding: the same 1/1,005 prediction differs.
- Final rounding under either seed: zero prediction differences.
- Float-seed arms FF/FQ: 648/1,005 correct; file macro 0.8468490903759225.
- Quantized-seed arms QF/QQ: 647/1,005 correct; file macro 0.8467041628396905.
- Both old floating and integer controls reproduce exactly. No weights clip.

The changed row is fold 1, identity
3ebcca401bbfa6a919a13a9c21f77000c02a7b40a41c64dd7358bffb940882bf.
Its true label is M04. FF/FQ predict M04; QF/QQ predict M00. Raw-x/common-weight-unit
float top margins are 0.0012061261983757343 and 0.002975290238856454. Full logits,
all per-row predictions and margins, fold statistics and weights are retained.
M00's class confusion is unchanged by this seed intervention.

This isolates deterministic seed-quantization sensitivity within this fixed
algorithm and reused development corpus. It does not identify the cause of the
broader generalization deficit, establish unseen-data benefit, justify choosing
an arm, or authorize model adoption. One extra correct development row is not
reported as an independently validated improvement. The earlier result that
final pooled-weight rounding changed no predictions remains true. Neither result
means parameters or logits are unchanged: all perturbation measurements remain
in the report. No public reward, deployment or model update occurred.

## Isolation, numerics and review

Only train.json and the previous TRAIN-only control report are loaded as task
data. No historical calibration/evaluation/consumer file is accessed. Every fit
and its seed exclude the scored source files. The two seed arms share exactly
the same seed identities, fit rows, features, class weighting, optimizer, regularizer
and step counts. Integer scores use exact int64 dot products; reported integer
logits are divided by 1024 to share units with raw integer x times float weights.
np.argmax retains lowest-index tie-breaking.

An independent reviewer replayed the runner with output redirected: the report
was exactly equal and weights byte-identical. A separate calculation verified
every prediction/logit, quantization array, seed identity and metric. The packaged
verify.py also checks those values and all OOF accounting without refitting.
Python 3.12.14 / NumPy 2.3.5 is the measured host, not the repository's pinned
NumPy 1.26.4 qualification environment. This makes no Rust/production qualification
claim. The five folds are paired development partitions, not independent trials.

## Reproduction and frozen bytes

report.json.gz and weights.json.gz are deterministic gzip wrappers around the
unchanged result bytes. decoded-hashes.json binds the originals; SHA256SUMS binds
the published package. No trained service or active model pointer consumes them.

    python evidence/seed-final-quantization-20261103/verify.py
    python evidence/seed-final-quantization-20261103/reproduce.py

verify.py replays stored weights without refitting. reproduce.py performs the
fixed diagnostic in a temporary output directory and compares report and weights
byte-for-byte; it does not overwrite the evidence. The existing NumPy/cryptography
and repository source dependencies are required. The original source routing
training input and previous OOF report already live in this repository and their
hashes are verified. Do not substitute other data or use this script to tune on
historical held-out partitions.
