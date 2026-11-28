# Private checkpoint activation profile and static runtime fields
This is a typed, no-output projection of the original activation
metadata predicates. It operates on already-held strings and does not
authenticate their origin, parse raw JSON, assert an actual runtime
observation, or bind the typed fields to the original raw activation pin.

`TAP1\0\0\0\0` is followed by 32 independently supplied expected
checkpoint digest bytes and five little-endian u64 words: threads,
forward calls, hook calls, parameter count, and Boolean flags in bits
0–3 (base-only, training, local-files-only, trust-remote-code). Then
fifteen u64 byte lengths followed by valid UTF-8 text in this order:
schema, checkpoint SHA text, dtype, origin, scope, producer SHA text,
prompt SHA text, manifest SHA text, device, storage dtype, Python,
Torch, Transformers, Safetensors, NumPy. Every string is at most
256 bytes in this private wire and the total extent at most 4,040.
The 384-byte work arena holds span metadata and literal text.

The original ordered predicates are profile/schema then checkpoint
digest grammar and equality then remaining profile constants, followed
(in the original with a shape/token stage in between) by producer,
prompt and manifest digest grammar, then all static runtime constraints.
Shape/token/bits and raw pin/parser are outside this layer. The original
reference invokes private `activation` through a test-only wrapper on
the unchanged full locked module with valid inert shape and bits and
an in-memory fixture pin. No real runtime data, I/O, activation, or
authority is used.

Status 0 indicates all scoped value checks passed; 1 is original
profile, 2 hash text format, 3 static scope. Status 100 is wire
shape/UTF-8 and 102 scratch capacity. Neither success nor failure
changes output, and no step constructs verified material.
