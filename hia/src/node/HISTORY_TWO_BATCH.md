# Private held two-batch ancestry and byte cutoff

`HPT00001` is a bounded one-call composition over immutable synthetic typed
projections. Bytes 8–31 hold the second batch row count (1–64), window limit
(1–16) and seed count (0–limit), as LE64. Bytes 32–127 hold start, after and
genesis IDs. Bytes 128–143 hold the two absolute exact batch ends, as LE64.
The seed IDs start at 144, then 64 rows and then the second batch's rows
use the existing HPF row format. The single input loan is at most 1 MiB.

The first batch must not finish at either stop. The second begins at the
actual immutable parent offset returned by the first, resets ordinal to
zero, and appends into the same private 512-byte rolling deque. It must
finish at after; continuation, stopping after only one batch, and an empty
second batch are outside this profile. Both row extents must be consumed
exactly. The already-published HPF edge and deque routines are shared.

The exact remainder must have one (32-byte ID, LE64 wire length) pair per
retained slot, in deque order. Scan backward: at each visited slot compare
all ID bytes to the actual computed deque, then use the shared HPCB
length/cutoff decision. The boundary candidate is checked; older unvisited
IDs and lengths are not checked. The wire lengths are inert fixture
declarations, not evidence that packets exist or have been measured.

Success publishes total links, selected ID count and summed wire bytes
as three LE64 words, then exact chosen IDs in visit order, at most 536
bytes. Refusal never writes output: row failures preserve the old HPF
diagnostics, private frame/profile mismatches (including unjoined IDs)
are 100, and insufficient scratch/output is 102. No intermediate cursor
or deque is published and no mutable buffer is cast to an immutable one.

The exact source-bound original witness uses a query-only synthetic
in-memory SQLite transaction, calls the unchanged private ancestor fold
twice with its returned cursor and carried deque, then runs the original
packet selection loop with inert stand-ins for already-loaded packets.
Both stock backends compare 65-, 84-, 128- and 70-link traversals and an
original second-batch refusal. The standalone HPCB ABI and observed
behavior remain the same; its emitted bytes are re-qualified because
the decision moved to a shared helper. HPF source and old static
qualification are untouched. No live SQL, Node, packets or authority.

    python3 -B -m unittest -v hia.tests.test_node_history_page_two_batch hia.tests.test_history_page_cutoff

## Static qualification with the same held projections

A separate private qualification links the exact stock Selfhost object
into the unchanged source-bound two-batch Rust witness. After the two
recursive SELECT projections, original folds, and literal original
cutoff loop, the native entry receives that exact immutable projected
frame before the same owned in-memory SQLite read transaction rolls
back. SQLite reports Read on both sides of the call. The fixture checks
that capture, comparison, and rollback cause no row changes. No SQLite
handle or file path crosses the ABI.

The four successful projections, including all 128 links and both
800,000-byte boundary and first-record rules, and the original second
batch refusal match exactly. The fixture checks disjoint output and
scratch canaries and unchanged input, an exact one-member archive with
no imports or relocations, and the complete stock text in the linked
executable. The result qualifies an offline link with held byte
projections, not packet length acquisition, production history I/O,
or SQLite ownership in HIA.

    python3 -B -m unittest -v hia.tests.test_node_history_page_two_batch_held_link
