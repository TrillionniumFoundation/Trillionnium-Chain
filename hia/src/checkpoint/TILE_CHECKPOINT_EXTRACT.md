# Bounded same-byte checkpoint BF16 tile extraction

The private input is `TCE1\0\0\0\0`, 32 bytes of caller-held expected SHA-256,
a u64 little-endian expected byte extent, then one immutable disposable
checkpoint byte buffer. The original standalone size/prefix stages are
followed by the exact shared THV1 named header over the actual subspan and
actual remaining payload. Both its general interval coverage and exact
BF16 [576,576] target checks run before the checkpoint pin, preserving the
original error order. No caller-supplied selected offset is accepted.

The original checkpoint prefix is u64 little-endian JSON header length.
Native hashes the **entire same checkpoint buffer**, excluding only its
private framing. Only on matching the pin does it publish 8,192 opaque
BF16LE bytes: rows 0–63, columns 0–63, with 1,152-byte source stride and
128-byte output stride. The private frame cap is 1 MiB, so the checkpoint
itself is at most 1,048,528 bytes, narrower than the original. THV1 named
record/map caps also apply. Work needs 18,000 bytes and the output prefix
needs 8,192. No refusal modifies output; bytes after that prefix stay intact.

Statuses 1 size, 12 short prefix, 13 prefix header geometry, 14 pin;
THV1 statuses preserve their existing meanings. Other private errors
100 framing, 102 capacity, 103 narrower header profile, 104 SHA internals.
The official frozen original reader fragment is paired through an owned
test-only Cursor and inert fixture callback, stopping before quantization.
Native has no file or observer and does not admit or run any model, task,
proof, loader, provenance or material authority.
