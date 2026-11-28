# Held paired evaluation score

`paired_evaluation_score.hepta::f0` is a private, offline value kernel for a
bounded subset of the original formal `evaluation.assess`. It compares two
immutable **supplied prediction vectors**, not models. The original frozen
bundle caller scores a candidate against its selected control and three
ablation predictions after checking the bundle pin, calibration and partition.
This kernel does none of those upstream operations.

## Private EAS1 profile

One immutable buffer contains `EAS1`, followed by row count u8, caller's future
claim u8, comparisons u8, minimum clusters LE u16, then exactly the specified
count of 104-byte rows, with no trailing bytes. Successful calls accept 1–64
rows, 4–64 comparisons, and 20–4096 minimum clusters. The formal bundle caller
uses 4 and 20. The original supports up to 32,768 rows, 4,096 distinct groups,
and longer Unicode strings; this profile does not claim those wider forms.

Each row has three 32-byte fields, in order: task ID, source group, file.
Each is printable ASCII with canonical right zero padding; a full field needs
no terminator. Offsets 96–98 carry label, candidate class and reference class
(u8, each 0–2). Offsets 99 and 100 are independent source-group/file presence
bits; an absent field must be zero. Offsets 101–103 must be zero. At least one
nonempty effective group is required: the original uses `source_group` when
present, otherwise `file`, and both must agree if both are supplied. Task IDs
must be nonempty and distinct. Physical rows align both predictions to their
label by construction. Original list-length mismatch, other JSON types, and
longer or non-ASCII strings cannot be represented as accepted private inputs.

On success the first 88 output bytes contain 11 LE 64-bit words: group count,
wins, losses, comparison count, exploratory cluster gate, signed reduced mean
numerator, positive reduced denominator, integer exploratory score,
`future_window_observed` (zero), caller's unchanged future flag, and
`public_reward_eligible` (zero). The constant original reason is
“independent time/source-owner receipts must be verified by the accepting owner.”
The remainder of output and all scratch are untouched. Failures leave all
output and scratch untouched. Statuses 1–10 correspond respectively to
`MULTIPLICITY`, `MINIMUM_CLUSTERS`, `TIME_OBSERVATION`, `EVALUATION_LIMIT`,
`TASK_ID`, `DUPLICATE_TASK`, `LABEL`, `SOURCE_GROUP`,
`SOURCE_GROUP_BINDING` and `PREDICTION`. Status 100 is an invalid private
frame; 102 is a valid input with fewer than 88 output bytes.

## Exact arithmetic and evidence

For group size (s), the signed numerator is candidate-correct minus
reference-correct. The running sum uses integer numerator and product of group
sizes as denominator. With at most 64 rows, the product is at most
`3^(64/3) < 2^35`. The denominator and absolute numerator after averaging are
bounded by `64 * 2^35`, and scaling by 1,000,000 still fits 64 bits. GCD
reduction makes the signed mean exact, including zero and negative results.

The directional test runs only for positive mean, enough groups and wins
greater than losses. With (d = wins + losses), symmetry transforms the
original upper binomial tail into the terms from zero through losses. The
kernel cancels the recurrence's numerator and divisor by their GCD, then
divides the preceding coefficient before multiplying; integrality ensures that
division has no remainder. Individual coefficients fit u64 and the lower
tail is strictly below `2^(d-1)`. Instead of multiplying the tail by
`20 * comparisons`, compare it with the floor of `2^d / (20 * comparisons)`.
For (d=64), divide `u64::MAX` and account for one extra bit using the remainder.

The differential test invokes the unchanged original formal Python routine as
a separate isolated process. It checks the exact runtime source and all three
configuration digests before and afterward; compares typed outputs against
both stock native images; and checks framing, returned spans, and canaries.
The proof uses newly generated inert inputs. It is not training, inference,
work proof, model selection, adoption, independent future evaluation, or
permission to apply any update or reward.
