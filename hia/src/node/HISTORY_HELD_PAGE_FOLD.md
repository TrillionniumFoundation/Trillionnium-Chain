# Private held Node history page fold

`HPF00001` is the pure bounded record-fold portion of the original
`history_page_ancestors`, after SQLite selects one batch. It takes
no Node, statement, path, actual packet, or owner. It does not read
active State, run SQL, compute work, choose a chain, or qualify a
history service.

The input begins with the magic, little-endian u64 captured row count
(0–64), window limit (1–16), and seed window length (0–limit), then
32-byte start, after and genesis IDs. The seed window follows at byte
128 as consecutive 32-byte IDs in original deque order. Each row has
three pairs of LE64 SQLite class and byte size (the child ID, ordinal,
and joined parent ID), then the two HIR1 frame byte lengths. The payload
holds the actual three scalar values, exact child HIR1, and exact
parent HIR1. Each HIR1 cell uses the original bounded fixture format;
the aggregate immutable byte loan is at most 1 MiB.

Each selected row checks the full child ID and nonnegative ordinal
against the current cursor and completed-link count first. Then it
checks the complete original child SQL types and fixed widths before
the parent-present/join and complete parent type and width validation.
The original HIR1 rules are used with bounded subspan offsets; the old
HIR1 ABI and source are untouched. Child height must equal parent
height plus one. Only then does the row enter the rolling window
(evict from the front at the limit). The final parent must equal
after/genesis or the batch must have exactly 64 completed links.
The native private framing additionally requires the joined ID bytes
to match the child's stored parent and rejects presented rows with the
original SQL's excluded after/genesis IDs.

A success writes checked links, 32-byte remaining cursor, retained ID
count, per-call SELECT count of one, links count, and per-call retained
high water as 72 header bytes, followed by the exact deque IDs, at most
584 output bytes. It reports the observed original batch's per-call
counters, not elapsed time, a database connection, or historical
monotonic counters across calls. The private scratch is 512 bytes.

Native framing/capacity are 100/102. Original row observations are
40 unknown initial locator with no chosen rows, 41 unknown parent
after a retained local relationship, 42 local ancestry height/ordinal
mismatch, 10–14 for child SQLite type/sign, 50–54 for the corresponding
parent columns, 22–25 for the leading ID/ordinal/join columns, and
30/31 for original stored hash/work widths. Original non-local
`UNKNOWN_PARENT` is kept distinct from the same local diagnostic;
no output is published on a refusal. Original late refusals can leave
changes in the operation-local deque and counters. Native only uses
its private scratch for partial state; it does not expose a partial
result. Comparisons distinguish the two contracts.

The original witness builds the exact extracted private method body,
its literal recursive SELECT, inline record decoder, and used Work and
Error bodies, with the project's locked bundled rusqlite packages. A
test-only adapter holds one in-memory SQLite connection, a synthetic
genesis value, and the actual original counters; it is not a Node
instance. The fixture executes the same original SELECT to record
the ValueRefs, then uses the unchanged original private method to read
the same immutable synthetic database. Both stock machines check
full64/limit16, seed eviction, real original error precedence,
scoped local refusal, and atomic native output canaries. There are no
packet/body, cursor publication, network, reorg, durability, or
active-State results.

    python3 -B -m unittest -v hia.tests.test_node_history_page_fold

## Static link while the original read transaction is held

A separate private test links the stock Selfhost object into the exact
frozen Rust comparator. The fixture begins a transaction on its
query-only synthetic in-memory SQLite database and keeps that same
Rust transaction alive across capture, original fold, and direct
native call. SQLite itself reports a live read transaction before and
after the call; the fixture rolls it back and checks that no rows
changed. Only the immutable projected byte span and two disjoint
operation-local writable spans cross the native ABI. No SQLite
handle or path crosses. The test matches the complete ordinary Rust
observation stream, the full 64 links and 16 retained IDs, initial
versus later refusals, private scratch prefixes and public output
canaries. It verifies the entire linked native text, no native imports
or relocations before linkage, and one exact archive member.

This adds a same-transaction test of Selfhost linkage, not a Node
integration or replacement of Rust selection/transaction ownership.
The original dual-backend test is unchanged.

    python3 -B -m unittest -v hia.tests.test_node_history_page_fold_held_link
