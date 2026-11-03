# Independent replay and inference clarification

A separate read-only review reran the earlier train-only quantization diagnostic,
the source corpus audit and the direct-test ablation. All three generated JSON
reports matched the retained reports exactly. Both existing checksum sets passed;
no fit/score whole-file leakage was found in that review.

The earlier quantization README's sentence “Quantization is not the cause of
these observed pooled-model errors” is too broad. Both comparison arms start
from the same already quantized seed. The measured equivalence only shows that
final pooled-weight rounding and clipping did not change any of the 1,005
out-of-fold predictions. It does not isolate or rule out seed quantization effects.
The original plan, script, outputs and README remain preserved; this addendum
narrows the interpretation without changing experimental observations.

The inline-test intervention remains negative on the complete scoring population.
Identical optimization step counts do not mean identical FLOPs, and the candidate
also has fewer training examples. The result does not isolate a universal causal
effect of test syntax. No production change or efficacy claim is warranted.

Subgroup file-macro denominators are 67 files containing direct-test rows and
99 files containing other rows, versus 150 overall. Some files contribute to
both subgroups; subgroup macros are not additive. Row denominators are 264 and
741. Across five folds, pooled example evaluations fall from 482,400 to 355,680;
parameter-update counts are unchanged. “Fewer sample updates” in the original
README means fewer example evaluations per full-batch step. Deletion also changes
seed identities and within-class weights, so dataset size, initialization and
reweighting are not independently controlled.

The hypothesis used prior out-of-fold outcomes from this development corpus.
Whole-file fit isolation is not an untouched confirmatory evaluation guarantee.
Local commit order supports before/after chronology but is not an externally
timestamped preregistration. Related code across files and imperfect direct-test
detection further limit the inference. The independent review found no high-
severity integrity issue and judged this suitable to publish as negative
reused-development evidence with these clarifications.
