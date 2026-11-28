# One private Cell training coordinate

This pure slice starts after the active training stage has a gradient. It
uses one existing optimizer coordinate and a fixed 80-byte loan:
ten LE64 words for mask (0/1), existing step (unsigned), signed weight,
signed old moment, signed raw gradient, learning numerator/denominator,
momentum numerator/denominator, and clip bound. The output is a 48-byte
prefix: unsigned next step, then signed new weight, new moment, masked
gradient, clipped gradient, and change. Scratch is unused. Success leaves
the output suffix unchanged; refusal leaves every output byte unchanged.

The original update requires weight in ±32,767, old moment in ±i64::MAX,
learning numerator ≤2²⁰ and denominator 1…2³², momentum
numerator strictly below denominator ≤2¹⁶, and clip bound 1…2⁴⁰.
With up to 64 active rows, signed feature magnitude ≤8 and the original
logit/target limits, the raw gradient is even and has magnitude at most
137,988,390,912. These are private value/shape checks, not node admission.
The candidate does not compute the gradient or infer that any input came
from actual prediction or a selected model.

With an active batch the original increments the step before any masked
coordinate. A masked-off coordinate preserves its exact weight and moment,
with all three diagnostic stages zero. A trainable coordinate first clips,
then adds truncated old momentum. Unsigned magnitudes avoid signed overflow:
if the old absolute moment is q·den+r, the scaled magnitude is
q·num+floor(r·num/den); both terms and their sum are bounded. For the signed
sum, the sign and magnitude are tracked separately before checking the
original range. Given the admitted gradient and decay bounds this guard
is defensive: a maximum old magnitude loses at least 140,737,488,355,328
before the largest possible 137,988,390,912 gradient is added.

If the learning numerator is nonzero, the weight guard uses the largest
admissible moment magnitude:
floor((((headroom+1)·learning_den)-1)/learning_num). Headroom is
weight+32,767 for positive change and 32,767-weight for negative change.
After this guard the product fits u64 and the exact signed quotient is
subtracted. This preserves Rust truncation toward zero, including the
boundary with a nonzero discarded remainder. A zero rate still updates
the moment and diagnostics but not the weight.

Statuses are 100 for malformed/out-of-scope input, 102 for output
capacity, 201 for optimizer-step overflow, 202 for the defensive moment
range guard, 203 for trained-weight refusal, and 0 for success. The
private envelope is checked before original step/weight arithmetic.

The offline referee compiles the entire source-pinned private Rust train
function verbatim with its original types, arithmetic helpers, ensure,
and the locked Serde dependency graph. The tiny harness pairs synthetic
active rows with one enabled coordinate, checks that the real backward
stage generates the supplied gradient, and reads the actual update
stage. It uses a String diagnostic carrier rather than linking unrelated
Node effects. This covers one coordinate only: no real inference,
sampling, proofs, model or optimizer installation, or training loop.

    python3 -B -m unittest -v hia.tests.test_cell_training_coordinate
