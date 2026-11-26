# Native SQLite boundary: bounded reservation replay

This is a deterministic, non-authoritative replay of one original Rust ledger
call for an already bound existing slot. It is not a VFS, inode check, file
open, physical I/O budget, allocation quota, admission token, or replacement
for the original Rust owner.

The private input is seven little-endian u64 words: V1 (0) or V2 (1), old high
water, lifecycle record count, operation count, denial count, sticky failure
reason, and requested endpoint. Its fixed 56-byte output is new high water,
new lifecycle count, operations, denied, sticky failure reason, event flags,
and optional request value. Reason 1 means evidence margin; reason 2 means
inode endpoint. Bit 0 marks an emitted reservation record; bit 1 indicates
that the original V2 record carries the requested endpoint. These fields are
scoped observations, not a serialized lifecycle receipt. Original SQLite
statuses 0, 10, and 13 accompany the state after the attempt; malformed ABI
and short output refuse without publishing.

The comparison compiles the unchanged original Rust ledger and pins bundled
SQLite and the original Rust crate. It includes real original bound-slot
test states, V1 exact reservations, V2 64 KiB rounding and full 4 KiB step
coverage to 16 MiB, original evidence margin and sticky-error precedence.
The original VFS owns serialized evidence, residency, all live file and
sidecar identities, cleanup, and actual I/O.

## Existing-slot observation replay

`observed_bind_replay.hepta` models the original logical observation for a
known retained slot with short ordinary evidence and at most 1,017 existing
records. It consumes observed lengths, link state and identities; it does
not acquire, bind, or attest to a real file. Its private 25-word LE input
contains policy/action, six prior object words, the other-slot identity
bitmap and two pairs, five original counters/failure words, prior sum and
peak, then the five observed object words. Its 14-word output contains the
six resulting object words, five counters/failure words, updated peak,
event kind and optional actual request.

The original precedence distinguishes linked observation, extent, other
identity alias, replacement and existing reservation. Only the first V2
pre-I/O observation calls original admission. An ordinary bind can pass
despite prior sticky failure; an immediate failure does not overwrite the
first error. Tests reach the 1,016/1,017 evidence boundary through actual
original ledger operations. This is not a filesystem identity proof,
serialized receipt capacity, or live version of the original VFS.

## Close and collection replay

`close_collect_replay.hepta` models the accounting after a successful
underlying close that the caller has already observed. A 240-byte input
contains the selected slot, active main-handle count, cleanup-event count
and all three pre-close slot rows as little-endian u64 words. Each row
contains presence/main/linked/reserved flags, actual handle count, pending
open count, SHM references, high-water bytes, actual observed bytes,
generation, device and inode. Absent rows are entirely zero. The closed
slot has at least one open handle, the main count includes pending opens,
and cleanup evidence must have room for one short event.

The 104-byte output gives the new main count, new cleanup count, retained
slot mask, retained high-water total and the selected row after close
but before collection. An unlinked main object's charge remains until
the last main handle completes, including when a different retained
generation still has a main handle. Pending opens, reserved slots and
SHM references also prevent refunds. Two native backends compare all
fields with original Rust ledger observations under V1 and V2, including
the last of the 256 cleanup events and a close in slot 2. Status 100
refuses malformed or out-of-profile input, and 102 refuses short output;
neither publishes any bytes. This mode does not close an FD, evaluate a
failed cleanup record, serialize the original event, or own live VFS state.
