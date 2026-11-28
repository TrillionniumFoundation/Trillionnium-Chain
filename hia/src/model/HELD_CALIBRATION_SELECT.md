# Held four-control calibration selection

`held_calibration_select.hepta::f0` implements the numeric selection in the
unchanged formal `evaluation.select_reference` on one held inert calibration
table. It returns the winning name and all four exact group-macro scores in
original order: `current`, `best_single`, `mean_merge`, `pooled`. The first
maximum wins. Each source group has equal weight, irrespective of its row count.

This private profile neither emits the original **reference-lock** digest nor
approves a reference or verifies a frozen bundle, partition, or isolation. It
does not run a model, issue an update, certify future results, or grant
consensus, reward, or adoption authority.

## Private CAL1 frame

One read-only loan starts with `CAL1` (four literal bytes), a row count u8, an
exact control-set mask u8 (15), and three zero bytes. There are 1–64 primary
rows of 104 bytes, then exactly two side bytes per row. The first 96 bytes of
each primary row hold the same 32-byte printable ASCII task ID, source group,
and file fields as [EAS1](PAIRED_EVALUATION_SCORE.md), with canonical right
zero padding. Offsets 96–98 are label, `current` prediction, and `best_single`
prediction. Offsets 99–100 are source-group/file presence bits, and offsets
101–103 are zero. The two side bytes hold `mean_merge` and `pooled` for the
same row ordinal. Labels and all four predictions are in 0–2.

Validation preserves original control-set, row-order, duplicate-ID, label,
source-group binding, and prediction checks within the typed subset. The
explicit layout eliminates list-length ambiguity. Nonmatching control sets
are rejected; unknown JSON types, longer or Unicode identifiers, larger
original corpora and unmatched prediction vectors are outside this frame.
Malformed frame or reserved bytes use private status 100; status 102 means
a valid frame with fewer than 80 output bytes. Statuses 4–10 match the
[EAS1 error names](PAIRED_EVALUATION_SCORE.md#private-eas1-profile); status 11
means `CONTROL_SET`.

A successful result contains the exact name in 16 zero-padded ASCII bytes,
then four pairs of LE u64 numerator and denominator. The rational scores are
reduced. Any unused output suffix and all scratch are unchanged on success;
all output and scratch are unchanged on refusal.

## Exact grouping and qualification

Each group contributes one 0–64 row count and four 0–64 correct counts.
These fit separate seven-bit digits, with no carry between counts. The
kernel accumulates four numerators on the same product denominator, then
multiplies that denominator by the number of groups. For at most 64 rows,
the product of group sizes is below `2^35`; every accumulated numerator is
at most the final denominator, below `2^41`. Comparing numerators before
GCD reduction is exact and avoids cross-multiplication.

The two stock emitters are compared to the selected name from the unchanged
original `select_reference` and the four exact fractions from the unchanged
`macro_accuracy`. The test compiles the original Python source bytes in an
isolated interpreter and pins both original modules and all three imported
configurations. It does not use the reference-lock calculated by the
original call as evidence for the native result. It checks all tie subsets,
the maximum 64 rows, unequal group-size outcomes, row-order refusals, and
canaries. The paired scorer source and published ABI remain unmodified.
