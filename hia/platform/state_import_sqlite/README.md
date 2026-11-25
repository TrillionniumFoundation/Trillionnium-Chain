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
