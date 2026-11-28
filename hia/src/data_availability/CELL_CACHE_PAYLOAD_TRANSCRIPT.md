# Offline two-chunk read/absolute-seek transcript

This bounded pure operation observes multiple reads of the same immutable
declaration and two held chunks. The cursor starts at zero with no resident
row. The shared stock 1 MiB input loan is:

| Offset | Contents |
| --- | --- |
| 0 | LE32 canonical TCM1 byte length |
| 4 | LE32 first held chunk byte length |
| 8 | LE32 operation count, 1 through 8 |
| 12 | Operations: one-byte tag and LE64 argument per operation |
| after operations | Canonical TCM1 with exactly two declared chunks |
| after TCM1 | First and second immutable byte spans in manifest order |

Tag zero implements original absolute seek (even past EOF), and tag one
implements one standard read (capacity zero through 64 bytes). The
separate cursor planner covers relative seeks. Empty held spans are absent
data. No caller-supplied cursor checkpoint, chunk offset, selected digest,
resident flag, or verification result is admitted.

Output has 96 bytes per operation: LE64 status, cursor, resident marker
(zero for none, one or two for the declared row), and copied count,
followed by those bytes and zero padding through 64 bytes. EOF and empty
reads do not touch the resident row; absolute seek does not evict it.
A positive read below EOF reuses the published planner for index, offset
and truncation. It reuses a checked row only inside this immutable call.
On a slot miss, it logically evicts the prior row and checks the selected
row's raw SHA-256 before comparing its declared length. Per-operation
code 247 is absent/mismatched data; 248 is a matching digest with wrong
declared length. Both leave the cursor unchanged and clear the slot,
and the subsequent operation still runs.

The transcript is staged privately. SHA uses the established first
1,232 scratch bytes, state and manifest-row base occupy 1,232–1,255,
and records start at 1,536. Success only writes the selected output
prefix. Capacity/format refusal writes neither output nor scratch.
TCM1 diagnostics remain unchanged; private envelope and capacity errors
are 100 and 102 respectively. This is not the original general reader
or its 4 MiB per-chunk maximum.

The qualification uses the unchanged locked original TCM1 decoder,
the original store digest comparison, and source-pinned original Read
and Seek statements. Only the actual SQL/deadline calls are omitted:
the harness supplies two inert spans without constructing a store,
deadline, file, loader, lease, or owner. The resident marker is an
observation inside the call, not reusable cache state or a verification
token.

    python3 -B -m unittest -v hia.tests.test_da_cell_cache_payload_transcript
