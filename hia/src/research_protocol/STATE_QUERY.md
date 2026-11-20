# Native Research state queries

`state_query.hepta` implements normalized snapshot export, ordered current
references, all seven keyed getters and strict current-object lookup over the
privately admitted index. The shared [state value codec](STATE_VALUES.md)
computes exact canonical bytes and original leaf/snapshot hashes from these
native results. No host-language code constructs the queried business result.

## Semantics and private interface

Snapshot export retains protocol and authority values while sorting all seven
object buckets and the journal by their original complete keys. Current
references follow original kind order and then key order, with actual current
versions. A keyed getter returns the original Option behavior. Strict reference
queries preserve missing-object and wrong-current-version errors; a historical
version is not silently replaced by the current version.

The private frame begins `RSQ1`, an operation byte, and nineteen zero bytes.
All words are u64 little endian. Required scratch is the admitted index extent,
`266752 + 32 * typed_snapshot_bytes`.

| Operation | Remaining input | Native data |
| --- | --- | --- |
| 1 | Empty | Normalized typed snapshot |
| 2 | Empty | Ordered 48-byte current references |
| 3 | Kind 1–7 and raw 32-byte key | None, or kind word plus typed object |
| 4 | Complete 48-byte reference | Kind word plus strict current typed object |

The 128-byte result prefix contains data length, count, found flag, kind and
semantic code as u64 words at offsets 0, 8, 16, 24 and 32. Structured error
metadata occupies 64–127; data begins at 128. Getters use count/found 0 or 1.
Snapshot export uses count 0 and found 1. Reference export uses actual count and
found 1. Strict query errors use the graph's original codes 411 and 412.

Status 64 refuses insufficient scratch/output or arithmetic overflow; status 65
refuses malformed framing or unrepresentable typed input. Both preserve output.
Queries preserve the original copied snapshot and scratch tail; only their
private working metadata changes. A native owner must copy returned pointer
details before releasing memory and hide this continuation from public callers.
Caller-supplied arenas cannot create state ownership or authorization.

## Actual development observations

Three formal methods passed in 84.938 seconds with four native builds and 773
recorded calls: 422 original/native comparisons and 252 ABI controls. They cover
all seven getters, absent and present keys, versions 0/1/2/3/u64::MAX, growing
permuted maps, reversed journals, normalized snapshots and current references,
canonical bytes/hashes, reused arenas, every representative frame truncation,
invalid kinds and atomic capacity refusals. The unchanged original library's
actual getters and object methods supply independent expected results.
These finite kernel results do not qualify complete state ownership or retire
the original Research package.

```sh
python3 -m unittest hia.tests.test_research_state_query -v
```
