# Offline sealed descriptor to the original named integer-model handoff

The separate uninstalled selfhost-only Linux x86-64 executable consumes
the ordinary raw [IMP1](../../src/state/INTEGER_MODEL_PROJECT.md) input on
the exact [WQS sealed fd0 and anonymous stdout adapter](../worker_audit_sealed_query/README.md).
No filenames, argv, environmental selector, arbitrary fd, trusted State,
execution, persistent storage, or production routing is admitted.

The physical adapter is byte-identical. Its 65,536-byte held input and
exact EOF/seals/cursor checks stay fixed. This is deliberately narrower
than the named handoff's 296,016-byte already-held memory contract. Its
partitions are disjoint copies in the same private anonymous arena.
Unchanged named handoff machine text receives the exact existing 7,790
output and 37,296 scratch capacities. The separate syscall-free HIA
machine-byte thunk does not interpret input or propagate trust. It tests
the full packed result before reading six already checked output bytes:
`ILM2 02 00` yields the exact 7,788-byte ID-plus-model body; `ILM3 03 00`
yields the exact 7,790-byte body. Any other outcome returns zero to the
same transport refusal path. Memory status and process transport status
are separate: a failed semantic call emits no bytes and is not expected
to reproduce the named status as an OS return code.

The pinned builder rebuilds and verifies the exact original named stock
library, raw relocated-free kernel text and combined thunk import surface
before reusing the bytes unchanged; both the old adapter hash and static
system-instruction inventory are independently verified. No direct
named-backend qualification is claimed. Rust is not a runtime adapter.
Tests independently reuse the stock owner's actual immutable fixture
exports and the locked original Rust parser/load references; both model
versions, ordinary errors, unchanged State/counters, fd cap, missing seals,
nonzero offset and nonpipe stdout are verified in private scope.

```sh
python3 -B -m hia.tests.test_integer_model_sealed_descriptor --output NEW_PRIVATE_PROOF
```
