# Held calibrated paired evaluation

`calibrated_paired_evaluation.hepta::f0` composes the published private CAL1
numeric selection and EAS1 paired assessor in one bounded call. It selects a
control using only held calibration labels and four held calibration
prediction columns. Its native selected ordinal chooses exactly one of the
four held prediction columns on the **separate evaluation section**. The
caller does not supply the winner or a separately chosen reference column.

This matches the corresponding numeric `select_reference`,
`macro_accuracy` and `assess` calls over the admitted inert typed subset. It
does not compute a reference-lock digest, authenticate a frozen bundle,
independence, a future window or a dataset split, run a model, or issue
a decision, update, proof or authority. Physical separation of two sections
is not provenance or proof of disjoint source content.

## Private CAE1 frame

One immutable loan starts with `CAE1`, calibration and evaluation row counts
(u8 each), calibration control-set mask (exactly 15), comparisons u8,
minimum-clusters LE u16, and caller's future-claim u8. Both sections must have
1–64 rows. Each section starts with its primary rows, then its own side
columns, with no padding between sections or trailing bytes.

- Calibration body is the [CAL1](HELD_CALIBRATION_SELECT.md) body, without
  its header: 104-byte identity/group/file/label/current/best-single rows,
  then two row-ordered bytes (mean-merge, pooled) per row.
- Evaluation primary rows use the same [EAS1](PAIRED_EVALUATION_SCORE.md)
  104-byte shape: task ID, source group, file, label, candidate, current,
  presence bits and reserved bytes. Evaluation side rows hold exactly three
  bytes in order (best-single, mean-merge, pooled).
- All classes must be 0–2. Validation is scoped per section. This profile
  refuses an invalid nonselected prediction too, whereas the isolated
  original `assess` only receives the chosen prediction vector. Shape
  mismatches, original wide or Unicode strings, and misaligned original
  lists are not representable as accepted CAE1 rows.

Once the entire shape is bounded, calibration validity precedes evaluation
policy and row validity. Shared CAL1/EAS1 numeric status mappings and
framing/capacity codes remain in use. The private outer framing/shape
checks may precede semantic checks across physically invalid frames.

A successful result is the full 88-byte EAS1 result, followed by CAL1's
80-byte numeric name and exact reduced scores. Its observed future and reward
fields remain zero, independent of the recorded caller flag. The same output
capacity is checked before any publish. Input, output suffix and all scratch
stay unchanged; a refusal leaves all output unchanged.

The published CAL1 and EAS1 standalone ABIs retain their identical physical
input and output shapes, default column bindings, and refusal behavior.
Their private inner helpers accept explicit held offsets for composition.
The qualification invokes the unchanged original source in a separate
interpreter, then compares both stock emitters on new synthetic data, exact
64+64 rows, all four native winners, mixed group sizes, ties, failures and
canaries. It independently reruns both previous full differential suites.
