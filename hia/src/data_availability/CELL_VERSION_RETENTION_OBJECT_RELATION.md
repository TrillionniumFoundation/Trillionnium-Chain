# Immutable ordered TCA3 object relation

This is the original typed object subrelation, not a TCA3 decoder,
commitment, loader, owner or store. It checks the disclosed ordered
expected manifest roster against exact canonical TCM1 object bytes,
never a host prehash or positional claim alone. The expected roster
is borrowed data: this diagnostic does not establish its source or
bind it to a decoded TCV1 value.

The bounded adapter is at most 1 MiB. It starts with `NTO30001`,
the declared store ID, big-endian u64 capacity, outer operation
and funding IDs, big-endian u64 start and end heights, and two
big-endian u16 counts. The equal counts must be 1–512. For each
ordered pair: a big-endian u32 length and expected canonical TCM1,
two 32-byte object IDs, three big-endian u64 object terms (start,
end, maximum repair), a successor tag (zero or one), two 32-byte
successor declarations when present, and a big-endian u32 length
and actual TCM1. Trailing bytes are refused. The original outer
configuration and all gates before this subrelation are separate;
this diagnostic does not validate them.

Within the shaped range it checks the complete actual TCM1 values,
original object terms and supported successor declarations, then
requires the expected bytes (same canonical length and content).
Per-object duplicate operation and funding identities are rejected
before lease coverage. After the last declared pair is consumed,
the complete sets, including their outer fields, must be disjoint.
Each size is rounded up to 4,096 and added before the capacity
comparison. At most 512 individually validated objects of at most
64 GiB each cannot overflow the original u64 sum. The full outer
serialized-size condition is deliberately not inferred from these
individual loans. The private workspace is 4,104 bytes for borrowed
offsets. It can change on refusal. The output is never written.
Zero reports only this subrelation, not an approved contract.

The direct oracle constructs typed fixture manifests, closures, pins,
and version in memory via frozen original functions, without cache,
store, network, actual loader, funding or other actions. It calls
only public typed `CellVersionRetentionContractV3::validate` and
compares explicitly selected diagnostics. Fixtures include the full
512 objects and aligned limit/one-page-short cases.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_retention_object_relation
```
