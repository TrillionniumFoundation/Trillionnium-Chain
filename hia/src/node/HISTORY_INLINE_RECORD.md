# Private fixed-column Node history row observation

HIR1 mirrors the original private history inline row conversion, not the
history traversal or a database owner. The input is one immutable synthetic
tuple of already held SQLite storage classes and bytes. Header HIR1 followed
by four zero bytes, then four descriptors, each little-endian u64 storage class
and u64 length. Payloads follow in column order with no trailing bytes.
Classes are NULL=0, INTEGER=1, REAL=2, TEXT=3, BLOB=4. NULL has no bytes;
INTEGER and REAL have eight bytes, with INTEGER the original signed i64 bits
in little-endian order. TEXT/BLOB bytes are limited to 4,096 per column in
this private fixture. These bounds are not limits on original SQLite input.
No value is interpreted as a path, state, authorization, or ancestry decision.

After envelope checking, each storage class converts in original order:
nullable BLOB parent, nonnegative SQL INTEGER height, BLOB work, BLOB root.
Only then are exact widths checked in parent/work/root order (32 when
present, 64, 32). Errors 10–13 represent the original InvalidColumnType at
columns 0–3, 14 the original signed SQLite height out-of-range, 30 the
original STORAGE_HASH error, and 31 STORAGE_WORK. Framing (100) and caller
output capacity (102) are private ABI errors, not SQLite results.

Success writes exactly 144 bytes: u64 parent present, 32 parent bytes (all
zero when absent), u64 height (little endian), 64 work bytes in original
stored order, and 32 root bytes. No output or scratch bytes are changed on
any refusal; scratch is unused. Wider BLOBs are rejected without moving
their payload into output. The fixture uses no SQL operations in HIA.

The frozen Rust comparison uses actual unmodified InlineSqlBlob, inline_record,
Record, ensure, and original Work/Error types from the locked Node crate.
An in-memory SQLite connection runs only a bound constant SELECT; the same
row supplies both the recorded ValueRef classes/bytes and original result.
The original checked semantics are compared to the stock Direct and Selfhost
memory entries. This does not exercise Node.db, real packets, history cursor
selection, rollback, cancellation, commits, recovery or production authority.

## Private same-statement linked caller

In a second qualification, the same unchanged HIR1 Selfhost object is packed
as a single import-free member in the named static fixture library
libtrnm_history_inline_record_fixture.a. The pinned original fixture source
is captured unchanged except for one scoped comparison call immediately
before the row's final use and statement advancement. The observed Row is
still live: original conversion and native comparison share its exact
bounded HIR1 bytes, and the fixture obtains the same ValueRefs again before
advancing. The native call returns its complete packed status; the caller
checks output and both buffer canaries before recording any result.

The qualifier reads the exact stock text back from the final linked x86-64 ELF
at its unique f0 symbol, not merely from the static archive. This is a private
linkage/ownership observation, not a native SQL engine, driver, path or
Node.db integration. It runs only synthetic in-memory bound SELECT values.
The earlier exported-row differential independently retains both stock
backends; this linked observation is Selfhost only.
