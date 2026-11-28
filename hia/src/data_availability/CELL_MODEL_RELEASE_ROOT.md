# M09 TMR1 declared model release metadata

This private HIA byte entry observes the unchanged Rust
[`CellModelReleaseRootV1::decode`](../../../trillionnium/crates/trnm-data-availability/src/cell/model_root.rs),
its outer ID, its router-roster commitment, and the number of declared
direct parents from one immutable canonical TMR1 record. The Rust production
caller is unchanged.

The original order is outer extent/version/embedded extent, complete TCD1
then declared lineage framing and strict nonzero byte order, then the
router-roster comparison. The embedded validator uses its original TCD1
and TCR1 limits through the shared checked offset/extent core. The roster
hash is computed, not supplied by a caller: its original domain is followed
by the big-endian count of Router-role rows (including zero), then canonical
file-path order with the existing path length, path, manifest ID, payload
digest and declared size. Role, dependency list and other-role rows are not
in that domain. The original outer hash commits the whole raw canonical
record under its separate domain.

`f0(readbuf, mutbuf, mutbuf) -> u32` writes exactly 68 output bytes on
success: TMR1 ID, independently computed roster digest, and LE32 declared
parent count. On refusal output and the input loan remain unchanged; scratch
is private and stays within the existing 13,944-byte TCD1 workspace.
Outer statuses 50/52–56 and original nested statuses are distinct; ordinary
Rust truncation uses the same I/O-error status 2 across layers. Private
capacity and internal hash diagnostics remain 102 and 103.

The unchanged original parser/encoder and locked SHA-256 are used in a
genuine differential against both pinned emitters. Tests include empty,
mixed and all 256 Router rows, BE16 count, maximal lineage, and independent
digest domains with earlier nested/lineage refusal precedence. The standard
native test loan represents all valid canonical TMR1 values (conservative
225,606-byte upper bound). Malformed overflow cases beyond the 1 MiB loan
are tested only by the Rust original; format limits are not enlarged.

This does not fetch or verify parent objects or ancestry, check a trusted
pin, open files, resolve paths, authenticate a publisher, execute a model
or loader, read payload, use network/storage, or allow selection/adoption.
