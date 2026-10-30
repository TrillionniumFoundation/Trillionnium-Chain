# PN1 finite native I/O observations, 2026-10-25

These are uncommitted overlays on Chain `630f871293e48588e0a1ceae7ceb64973d3ec31d`,
not qualification of that clean commit or a prospective merge. The
[index](index.json) hashes verbatim execution receipts. Complete raw directories,
frozen sources, inputs, witnesses and ELF files remain in the indicated local
archives; this compact index does not include or independently reproduce them.

The original [Node001 failure](node001-original-failure.json) retains the omitted
trusted pool prerequisite and sticky lower lock failure. [Node002](node002-original-failure.json)
actually fixed pool setup and completed two public reads, but its normal cold
reopen still failed. Its error 10 is a subsequent sticky admission refusal; the
first lower failure is xLock 3850. A separate frozen Node001 strace reproduction
observed an O_RDONLY descriptor receiving a write-lock request and EBADF. That
diagnosis is not an errno observation from Node001's original run or Node002.

The [read-only initialization repair](readonly-close.patch) checks the actual
SQLite read-only state, sets and reads back NO_CKPT_ON_CLOSE before SQL access,
and propagates every error. Writer WAL, FULL synchronization, capacity and
sticky failure behavior are unchanged. This connection configuration is not an
immutable authorization boundary; callers can still change it through SQLite's
shared API, and any resulting lower error remains a failure.

The final [Node004 finite control](node004-finite-pass.json) passed with the
boxed private join metrics representation: 256 original signed transfers,
one retained complete proof actually verified and admitted, two original public
Head/History reads with their original two-second deadline per call, one actual
service join, all original
connections closed, then same-domain AuthV1 cold reopen and readback. It has
20 required metadata files and 27 healthy complete RootReceipt rows. The final
test SHA-256 is `411379e845cd1b8440c35d4db8f329c166287fdf1a2911d125391c6585dc6695`;
the production SQL factory is
`38d3355f4ba2bb7d619bbd797f295dcb38e3390e59117e1346a9c914b60ba70c`.
The [ten original VFS controls](vfs003-finite-pass.json) also passed with 89
exact receipt rows. [Strict Clippy](clippy006.json) and the
[read-only formatting check](fmt-check.json) passed; earlier actual failures
remain archived. These counts do not include a new W1 proof search, the private
cfg(test) reader, a full 4,097-identity run or a crash/recovery campaign.

The native I/O controls retain the declared 4 CPU/16 GiB run scope, 3 GiB AS
and 16 MiB FSIZE limits per native process, and an 8 GiB whole-artifact ceiling.
Each Node owner retains seven roots and three retained 16 MiB real-inode slots
per root. Logical inode-length reservations are not allocated-block or
filesystem-metadata quotas. Full collection guards remain false.

The [independent dependency audit](sqlite-wal-reset-dependency-audit.json)
identifies a separate known WAL-reset issue in bundled SQLite 3.46.0. Official
[WAL documentation](https://www.sqlite.org/wal.html#walreset) identifies fixes in
3.51.3 and later, with 3.44.6 and 3.50.7 backports. The generic factory permits
multiple writable connections, so Node's single-writer owner and Cell's scoped
serialization cannot qualify every factory consumer. No historical corruption
is asserted. A reviewed dependency repair, lock/graph update and fresh ABI
witness/native controls remain required before general persistence acceptance.
