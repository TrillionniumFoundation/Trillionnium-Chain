# Immutable TCD1 declared-context comparison

This private value entry reproduces the original pure
`CellReleaseClosureV1::verify_for_loader` metadata predicate. The name
of that original function does not imply an actual loader call or
authorization. The supplied expected context is a declaration, not a
trusted pin; the entry opens no object, path, model, loader, or store.

One borrowed input (at most 1 MiB) contains the exact TCD1 bytes,
followed by an expected descriptor, then its big-endian u32 byte length.
The descriptor has tag `VRLC0001`, a 32-byte declared closure ID,
big-endian u64 generation, 32-byte profile, big-endian u64 payload and
chunk caps, big-endian u16 family length and role count, the five
32-byte context declarations, the family UTF-8 bytes, and role codes.
The original typed domain is represented by bounded fixture data
(family at most 4,096 bytes; at most 1,024 role entries). The TCD1
portion uses the existing exact decoder and original digest and is
not replaced by a caller-supplied parse or hash.

After canonical TCD1 validation, the original comparison checks all
context fields, generation, profile, and the recomputed closure ID.
Both declared budgets must be positive. Required roles must be
nonempty, distinct, and present in the actual TCD1 roster; order need
not be sorted. Finally the exact sum of declared file lengths must fit
the payload cap. The sum is bounded by 256 times 64 GiB. TCD1 knows
no actual TCM1 chunk counts, so this does not prove a TCV1 chunk
budget or full TCA3 contract. Bytes for other roles are not skipped.
Neither input nor output is changed. Scratch (13,944 bytes) may change.

The original oracle constructs and round-trips synthetic TCD1 values
using the unchanged public Rust crate, then calls only the pure
comparison. The test covers all context bytes, role order and
duplicates, exact upper-size metadata and error precedence.
No credential, authorization, custody, or admission is created.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_closure_declared_context_relation
```
