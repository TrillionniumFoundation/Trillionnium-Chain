# Private model source revision value
This bounded immutable projection implements original public
`model_task_windows_v1::source_revision` for inert source descriptions.
It does not access files or repositories, prove origin, evaluate a window,
interpret labels, train, sign, or establish authority.

The packet starts with `MSR1\0\0\0\0`, then little-endian u64
repository length (at most 256) and task count (3 to 8, narrower than
the original maximum of 32). Exact repository text follows. Each task
has four little-endian u64 words: path length (at most 256), declared
hash text length (at most 128 transport, exactly 64 for a candidate
hash), content hex length (at most 16,384), and the u8 label in a u64
slot. The three exact data spans follow. Boundary limits are checked
before variable-width access. The maximum transport size is 134,680
bytes. The label is faithfully carried but does not affect this original
value calculation.

Original priority is repository, task count, then each task's valid
strict bytewise path order, canonical lowercase content hex containing
non-NUL ASCII bytes, declared hash grammar and SHA-256 equality.
The final hash is raw SHA-256 of the exact sorted-key compact JSON with
files in input order and original JSON string escapes. All hashing
buffers and intermediate JSON stay in 28,672 disjoint scratch bytes.
Output is its 32-byte digest only on success; unused suffix is preserved.
Statuses 1–6 represent the original refusal classes in the above order;
100 is private malformed transport, 102 capacity and 103 internal hash.
