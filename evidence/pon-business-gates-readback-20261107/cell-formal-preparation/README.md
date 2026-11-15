# Final Cell formal preparation

This is a local material-preparation record, not a test or proof-execution result.
The actual selector in model_loop.py selected 260 Rust source paths (M00 26,
M04 21, M10 213). Together with the historical portability inventory there
are 261 unique required blobs. The complete historical traversal also needs
153 tree objects and the exact source commit: 415 unique objects total.

Before preparation 399 were present and 16 blobs were missing. Only those
16 missing blobs (311,117 raw bytes) were added from the independently
hash-verified retained original pack. The original repository then read all
415 complete object contents successfully with GIT_NO_LAZY_FETCH=1 and
GIT_NO_REPLACE_OBJECTS=1, and each Git object SHA-1 was independently checked.
All three original model fixture files were unchanged and matched HEAD.

The original inventory lookup failed exit128; the first promisor batch also
failed exit128 at the first missing object. Both failures are retained. An
isolated bare repository with no remote and a read-only alternate to the
original object store enumerated the full missing denominator. This view did
not change the original repository configuration. Missing contents came only
from the original 261-blob pack, verified in a separate isolated repository
with strict index-pack. There was no GitHub or network operation.

HEAD/refs/tracked status were equal before/after the additive write. Root's
concurrent untracked evidence was present, so this record does not assert a
clean full source tree. No source/fixture/ref/FETCH_HEAD/runtime/30s deadline
or global Host setting was changed. No formal, native or benchmark command
was run. The final 202 formal tests still require actual execution on the
committed combined source, using the recorded real interpreter identity.

The handoff core renames the initial ambiguous refs_commands_used field to
ref_mutation_commands_used. Read-only for-each-ref was performed; the raw
producer core and output remain in observer/. Only the field name was clarified.
