# Private original model tasks root
`tasks_root.hepta` implements public `model_task_windows_v1::tasks_root`
on bounded immutable synthetic values. It accepts the existing MSR1
source-revision frame plus 32-byte family and 32-byte claimed revision.
It reuses the original native source-revision relation on that exact
borrowed input, and checks the claim only after source checks. Actual
labels 0–2, distinct declared content hashes and all three classes are
required as in the original. The input profile is 3–8 rows (original
3–32), with the existing per-row bounds, and needs 49,152 bytes private
disjoint scratch.

The original ASCII token rules start with a letter or underscore,
continue with alphanumerics/underscore, lower-case, exclude `trnm`-prefix
tokens and three exact class tokens, and cap at 1,024 included tokens.
The SHA-256 token digest chooses the original signed 256 counter buckets,
then counts clamp to [-8,8] and append bias 8. The same 257 values are
serialized as little-endian i16 for row IDs and canonical JSON integers
for the final task list. The exact PoN row transcript also binds
family/repository/revision/path/content/label; source group is raw
SHA-256 of its source path. The final PoN root hashes the original
sorted-key compact JSON in admitted order.

Status 1–6 mirror original source-revision checks, 7 is claimed revision,
8 label/content alias and 9 missing class. 100 denotes private wire,
102 capacity, 103 internal hash. Only a success writes 32 output bytes;
the unwritten suffix is preserved. This pure local identity is not
a source repo observation, task qualification, execution, training,
signing, deployment permission, production or live trust.
