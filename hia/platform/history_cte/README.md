# Fixed in-memory original history CTE projection

This private fixture progresses past synthetic row transport: HIA opens its
own SQLite `:memory:` connection through the unmodified, independently
qualified TaskKernel provider. HIA creates the fixed `blocks` table and
inserts four fixed generated rows, enables `query_only`, begins a read
transaction, then prepares and executes the exact bytes of the frozen
Rust recursive ancestry SELECT. There are no accepted paths, SQL, data or
database/statement handles in the test input, just one of three fixed query
modes. It opens no database files and never borrows a Rust SQLite pointer.

HIA supplies all four binds (three 32-byte BLOB IDs and the original
INTEGER 64), checks the returned 11-column statement width, and requests
each current row's typed bytes before the next real `sqlite3_step`. It
retains at most four rows under the synthetic profile. Each of eleven cells
in SQL order is recorded as LE64 storage class, LE64 width, and exact raw
value (0 for SQL NULL translated from provider class 5; INTEGER 1 with
eight signed bits; or BLOB 4 with up to 64 bytes). Other types are outside
this fixture. A real empty result is distinct from absence of a projection.
The data output consists of an LE64 observed row count and those cells.
This interface does not check or publish an ancestor verdict or call
the separate HPF/HPT consumers.

The unchanged provider implements actual SQLite operations. The isolated
host loads the exact sealed HIA/provider artifacts and passes the finite
requests and exact replies byte for byte. It refuses any OPEN other than
the fixed `:memory:` and any PREPARE outside the exact ordered six
statements. It does not generate SQL, choose cells, parse the projected
rows, synthesize provider results, or acquire a session for the native
code. HIA stages only private bytes until the actual SELECT finalizes,
COMMIT finalizes, and CLOSE succeeds. Fixture mode three is a private
refusal before opening. The host reset must observe zero leftover resources
before returning a successful projection. The fixture does not inject
post-open SQLite finalize or close failures. The literal SQL over HIA machine instructions is checked
at the actual mechanical PREPARE boundary, including frozen CTE bytes.

The locked unchanged Rust harness independently makes the equivalent
in-memory fixture with typed bound inserts, runs the same captured
original CTE, observes original current-row values, and also calls the
original private read against the same snapshot as a control. Direct and
Selfhost each compare all three exact typed outputs and observe
mechanical lifecycle. There is no production integration, filesystem or
VFS migration, underlying SQLite engine replacement, packet read, work,
authority, or active Node state.

    python3 -B -m unittest -v hia.tests.test_node_history_cte_acquire
