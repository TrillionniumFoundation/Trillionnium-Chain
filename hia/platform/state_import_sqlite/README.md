# M13 read-only SQLite snapshot projection

`cold_read.hepta` executes the SQLite read transaction and framing policy in
stock pinned Selfhost HIA. It uses the existing, independently checked native
TaskKernel mechanical provider for SQLite 3.54.1 calls. The fixture host owns
private allocations and forwards the native request span unchanged. It does
not choose SQL, inspect result fields to decide what to read, compute the
native projection, or turn a refusal into success.

The first private input supplies the expected uppercase plan and schema
digests followed by the owned fixture path. Each subsequent input is the
exact preceding provider response. A 1 MiB HIA continuation retains its
progress, statement and database handles, counts and staged projection.
Status 198 returns only a mechanical request descriptor; status 100 provides
no projection. On status 0 the published length describes bytes at offset
4,096. Open uses READONLY and NOFOLLOW; the SQLite image is never replaced.
The continuation ends its read transaction and closes the actual handle
before publishing. On failure the provider's owner reset finalizes retained
statements and closes the read transaction/connection. The portable runner
uses one isolated process per case and seals both actual ELF images.

For review, the SQL embedded in the native requests is equivalent to:

1. `BEGIN DEFERRED`.
2. Select the singleton's nine original metadata fields and row count. This
   statement checks the original application ID, user version, WAL mode, and
   exact two named SQLite tables. The seven digests must be 32-byte BLOBs;
   both context digests must be nonzero; row count and generation must be
   nonnegative INTEGERs. The continuation compares the expected plan and
   schema and enforces the original count bound.
3. Select the original rows in `ORDER BY namespace,key`, checking original
   BLOB types and field sizes before framing, and require the exact count.
   For every row, HIA decodes the three canonical hex fields to their
   original bytes and applies the original `ExportRowV0::canonical_digest`
   domain and big-endian length prefixes. It streams the resulting 32-byte
   digests in order behind the raw `trnm.migration.target-rows.v0` prefix
   and compares all 32 bytes to the persisted digest from this transaction
   after SQLite returns DONE. A mismatch fails without COMMIT or output.
4. `COMMIT`, finalize, and close.

The diagnostic output is uppercase hex, colon-separated, LF-terminated.
Metadata follows the original field order, with integers encoded as 16 hex
digits. Each row has exactly its original namespace, key, and value. The
diagnostic is intentionally not an original wire format, a cryptographic
readback, or a substitute for the retained verified-snapshot install. This
slice does not port original path/sidecar ancestry rules, WAL reconfiguration,
application state-root checking, or production wiring. The held-reader test
runs a real unrelated original writer process between metadata and row reads
of one native transaction, then separately checks the successor transaction.

Run from a normal pinned HIA toolchain and populated offline locked Rust cache:

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_cold_read -v
```

## Disposable empty-delta write

`empty_write.hepta` qualifies one transition with **no row mutations**. Its
private proposal supplies the complete predecessor and expected successor
metadata lines (489 bytes each), the raw 32-byte target-context and delta
digests, and then the original plan/schema and local test path fields. This
proposal is staged data from the test's unchanged original Rust delta
derivation. It is not an authority token or input from a network peer.

HIA opens the existing disposable database read-write with NOFOLLOW, sets
FULL synchronous mode for its own SQLite connection, and takes BEGIN
IMMEDIATE. It validates the exact predecessor in that same transaction,
including the actual persisted row commitment. HIA then prepares one fixed
metadata statement with two owned BLOB bindings; it changes only the target
context, last delta digest and generation, refuses signed generation overflow,
and requires an actual SQLite changes count of one. The original empty
delta's other metadata fields and all rows remain unchanged.

Before committing, HIA repeats the original-format read and row commitment
verification in its still-held transaction and compares the full reviewed
successor metadata. Any refusal has no published output and closes the
uncommitted transaction. Only successful commit, finalize and physical
connection close permit the successor projection to leave the continuation.
An exact empty replay of the already committed successor uses the readback
branch below, with no second metadata write or generation increase.

The test runs the original full locked Rust crate on separate SQLite files
for zero rows and nonempty state. It compares complete cold exports after
a real native write, verifies exact replay and wrong-binding refusals, and
kills the native process after the provider observes one actual updated
metadata row, then cold reopens the exact original predecessor in Rust.
There is no HIA app-root recomputation, production write path, signed
finality validation, or support for applying row mutations.

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_empty_write -v
```

## Disposable one-row DELETE

The same private writer admits a distinct `DEL1M13!` fixture prefix for one
reviewed original DELETE. It carries the original raw namespace and key
(each 1–64 bytes in fixed 64-byte fields), the old row's canonical digest,
and the reviewed next rows digest, application root, and row count. These
are fixture boundary limits, not changes to original StateImport limits.

Before writing, HIA finds exactly one matching namespace and key among the
actual ordered prior rows and binds that row to the reviewed canonical
digest, in addition to verifying the prior persisted rows digest and the
complete reviewed metadata. The exact same unencoded tuple is bound as two
SQLite BLOBs in one fixed DELETE. SQLite must report exactly one changed row.
A fixed metadata update binds the reviewed new count, rows digest and root
along with the original target-context and last-delta digests. The native
count must decrease by one. Within the same IMMEDIATE transaction, HIA reads
the remaining actual rows, independently checks their persisted digest, and
compares the complete successor metadata before committing. A root supplied
by the test is not an independently recomputed application root.

The real original SQLite owner independently derives and applies exactly one
DELETE to disposable databases. Its cold export must match after deleting the
only row and after deleting a middle row. Missing key, wrong prior row digest,
wrong successor rows digest and stale reviewed inputs must refuse publication
and leave original cold bytes unchanged. Separate process deaths are injected
after one real row deletion and after one real metadata update; original
cold reopen must observe the exact complete predecessor in both cases.

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_delete_write -v
```

## Disposable single INSERT

The distinct `INS1M13!` prefix uses the same reviewed metadata fields as
DELETE and adds an actual BLOB value of 0–128 bytes; its predecessor-leaf
slot is unused. The staged native reader checks the exact namespace and
key against every ordered predecessor row. It refuses an existing tuple
before any writable statement. The SQL is fixed `INSERT` without an
update clause, so a conflict cannot replace a row. HIA binds the namespace,
key and value as SQLite BLOBs and requires exactly one changed row and a
count increase of one. Full reviewed metadata, actual row commitments,
commit/close and publication are checked in the same way as DELETE.

The exact retained Rust delta derivation and SQLite writer establish
separate original successors for an empty value in an empty store and a
128-byte binary value inserted among existing ordered rows. A preexisting
key, stale proposal, excessive value length and wrong successor digest
must refuse without changing cold Rust readback. The fixture terminates
the native process after a real row insert and after a real metadata
update; neither uncommitted transaction may survive original cold reopen.

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_insert_write -v
```

## Disposable single existing-row UPDATE

The `UPD1M13!` fixture uses the bounded INSERT envelope with a required
prior row digest. Inside BEGIN IMMEDIATE, HIA matches the exact namespace
and key and the native digest of that stored row. A missing tuple, wrong
digest, or byte-identical value is refused before a writable statement.
The fixed `UPDATE ... SET value=?3 WHERE namespace=?1 AND key=?2` binds
the original key tuple and replacement value as three BLOBs. It cannot
create a new row. For this proven-existing row, it has the same row
effect as the retained Rust owner's original upsert.

HIA requires exactly one changed row and the same total count, re-reads
the complete actual successor and its persisted row digest, and compares
the reviewed metadata, including the supplied but not independently
recomputed application root. A result remains staged until the real
commit and connection close succeed. The exact original Rust owner
independently derives one changed row and establishes the cold successor
for both empty-to-binary and binary-to-empty changes. Cold Rust reopen
also checks that unrelated rows and order stay fixed and that wrong,
missing, already applied, same-value, or interrupted attempts fail
without a committed change. Both row-change and metadata-change kill
seams use the provider's actual one-row change observation.

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_update_write -v
```

## Disposable bounded mixed batch

The `BAT1M13!` mode admits exactly three 392-byte records: one DELETE,
one non-replacing INSERT, and one existing-row UPDATE. The input key
tuples must be strictly increasing in the original raw byte order
(namespace first, then key), independently of their operation tags.
This is one bounded route, not a general mixed-batch engine. Record
widths are the same as for the single operations; the UPDATE record
carries the reviewed final count, rows digest, and application root.

Inside one BEGIN IMMEDIATE, HIA completes the prior ordered scan,
recomputes its persisted row commitment, proves both required row
preimages and the inserted key's absence, and checks the complete
reviewed predecessor. It schedules all three typed SQLite statements
in order and verifies one physical change for each. There is exactly
one subsequent metadata update, one generation advance, and one
complete native successor read/row-digest comparison before COMMIT
and CLOSE. The supplied application root is reviewed data only.

The unchanged original Rust owner derives and applies the same three
ordered entries. Real cold SQLite exports must match exactly on a
three-row fixture and a seventeen-row fixture. Invalid order, a present
INSERT key, a bad last prior leaf and a stale predecessor are refused
without row writes. A wrong successor digest causes rollback even
after all three changes. The tests terminate the actual native process
after its first and third successful row effects and separately after
the metadata update. Every uncommitted case reopens to the exact
complete original predecessor.

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_mixed_write -v
```

## Disposable variable ordered vector

The `VEC1M13!` mode carries a little-endian u64 record count (1–8)
followed by that many of the same 392-byte typed records. Each record
supplies its DELETE, INSERT, or UPDATE tag. The tags may repeat and
have no required ordering; the binary (namespace, key) tuples must
be distinct and strictly increasing in the original order. The final
record carries the reviewed successor rows digest, state-root value
and count. The original single-operation and fixed-three fixtures
retain their distinct framing and checks.

Native HIA validates the vector before SQLite I/O and checks every
required prior digest, changed UPDATE value, and INSERT absence during
the held prerequisite scan. After validating the exact predecessor,
it computes the successor count from the inserts and deletes, applies
one typed SQLite statement per entry, and requires one actual change
each. One metadata statement and complete native successor/rows
verification precede COMMIT and CLOSE. The transaction remains
authority-free and does not recompute the application root.

The unchanged Rust owner independently derives and commits one
insertion, four ordered deletes, and eight mixed entries with repeated
operation kinds. Each length 1–8 has actual original cold parity. Tests
refuse zero or nine
entries, duplicate/unsorted tuples and wrong prior or successor digests,
and interrupt real row changes at the first and last steps and after
metadata update. Earlier single and fixed mixed tests are also retained.

```sh
python3 -B -m unittest hia.tests.test_state_import_sqlite_vector_write -v
```

### Original canonical commitment before a vector opens SQLite

The private `VEC1M13!` mode now derives the original ordered operation leaves,
incremental Merkle root and canonical delta digest directly from its one existing
proposal. It parses the reviewed predecessor target context, successor target
context, row commitments, application root fields and counts from that
proposal's metadata; the predecessor metadata must still exactly match the
actual held database. It binds the successor context, rows digest, root and
count to the raw typed fields the writer will use. The calculated digest must
match both the raw last-delta binding and its reviewed metadata projection.
A mismatch refuses before the native worker can issue provider OPEN.

The separate, existing typed-row validation, held-before checks, native
post-write row commitment and complete successor comparison remain necessary:
a correctly framed commitment to an incorrect successor is still rolled back.
The original fixtures and process-interruption controls exercise this distinction.
No second request format or host-computed digest is authoritative. Single and
fixed three-record fixture modes are unchanged. These checks establish
commitment consistency only; they do not verify checkpoint finality, sign or
authenticate contexts, recompute application roots, or route production writes.

### Exact empty replay

The private empty lane now derives the original empty incremental Merkle root
and canonical delta digest before opening SQLite. Its reviewed source/target
identities, plan/schema and unchanged row/root/count fields bind the
transition; the successor generation must be exactly one greater than the
reviewed predecessor. The raw successor bindings must match the reviewed
projection and computed digest.

If the held and row-digest-verified snapshot already equals the reviewed
successor in full, the empty replay skips all row and metadata mutation and
reports that actual unchanged generation only after COMMIT and CLOSE.
The nonempty replay rules are unchanged. The disposable Rust fixture tests
the real original apply and replay receipts, original cold reopen after each
branch and OS process termination before both initial metadata commit and
the replay's readback-only commit. This does not authenticate checkpoint
authorities or activate production writes.
