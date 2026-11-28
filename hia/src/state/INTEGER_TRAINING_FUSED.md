# Offline one-loan integer Cell train projection

This private entry computes the loss, backward and optimizer-update
numeric projections of frozen Rust Cell train from the same immutable
frame. It does not accept a supplied gradient, loss, previous phase
receipt, or trust token. The active rows and old parameter values remain
caller observations; the entry does not produce those rows via model
execution, decide routing, sample, verify proofs, authorize, or install
anything. The router, schema and model identity are not consumed or
changed by this projection.

The input is byte tag CTRN0002, LE64 active count (0–64), a reserved
LE64 zero, optimizer presence (0/1), old step, and five LE64 Training
words in existing CTUP0001 order (learning numerator/denominator,
momentum numerator/denominator, clip). Canonically absent optimizer
has zero step and zero moments. Three 24,672-byte planes (weights,
moments, mask) follow, each exactly 3,084 words in original
group/class/coordinate order. The immutable 2,096-byte row format is
identical to CTRN0001 and starts at byte 74,096. The physical input
ends there for zero rows, or at byte 208,240 for 64 rows. There is no
intermediate gradient plane in this input.

The exact checked backward projection occupies the first
B = 30,848 + 80 × count bytes of the scratch loan. It includes the
native-derived loss, base and routed delta gradients, unchanged zero
router gradient, and all row traces. The CTUP0001 update projection
occupies the next 123,392 bytes. Its optimizer reads the 24,672-byte
gradient span at scratch offset 8; no record written by the optimizer
can touch it. Both portions lie in the single exclusive scratch loan,
using checked scalar offsets and no view casts, model bytes copied out
and back, native allocation, or alias between loans. The full produced
prefix is copied once to a distinct output loan only after both parts
succeed. Maximum output and scratch each equal 159,360 bytes.

The two established wrappers retain exact framing and outgoing format
by sharing their named row validator and backward, update-domain and
update engines with this entry. The internal gradient-source selector is
fixed by its wrapper: CTRN0002 derives bytes in the private scratch,
while legacy CTUP0001 reads its own explicit supplied-gradient frame.
No wire selector enables the other branch. The legacy scalar interface
is unchanged by this composition. A helper refactor can change emitted
machine bytes even when the old standalone observable contracts match.

The private fused return codes are 0 success, 100 malformed frame,
102 insufficient extent, 201 step overflow, 202 defensive moment
bound and 203 trained weight range. Validate shape, every row and
all optimizer parameters before touching scratch, then check the
one nonempty-batch step increment. Original loss/gradient numeric
overflow is impossible within the accepted typed profile, permitting
that check before reserving staging. Zero active rows preserve the
original optional optimizer and never advance step. Check scratch
extent before computing; with sufficient scratch, arithmetic refusal
precedes insufficient public output. Malformed input, step overflow
and short scratch leave scratch untouched. The exclusive scratch
may hold bounded intermediates on arithmetic/refusal or short
output, but all public output remains unchanged. On success nothing
outside the exact produced prefix changes.

Tests feed inert signed rows to the unchanged source-pinned full Rust
train function, compare both stock emitters to all three stages, and
requalify the legacy backward, batch and coordinate interfaces
separately. No Node, real input, workload or model owner is invoked.

    python3 -B -m unittest -v hia.tests.test_integer_training_fused
