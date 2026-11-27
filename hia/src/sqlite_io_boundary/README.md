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

## Pending handle accounting

`handle_replay.hepta` compares the ledger transitions for reserving a
handle and confirming an already successful open. Its 80-byte input
is ten little-endian words: action (reserve 0, opened 1), main flag,
actual and pending handle counts, root active-main count, ordinary
event count, operation and denial counters, sticky reason and first
SQLite error code. It returns the eight updated observations and an
event tag in 72 bytes. Tags 0, 1 and 2 mean no event, reserve-handle
and opened. Reasons 0–4 mean no error, evidence margin, handle cap,
missing pending handle and earlier pre-growth extent cap. The return
status is the current original SQLite status, not the sticky code.

Reserve increments the original admission counter before checking sticky
failure or evidence margin, then checks the 32-handle cap. Opened does
not repeat admission: it consumes the earlier pending count without
changing root active-main accounting, even if a first error was saved
in the meantime. Original V1/V2 observations cover both limits and
precedence. The private input admits at most 1,017 existing ordinary
events and assumes the retained short event will fit the original
serialized budget. It does not model failure to serialize after mutation,
perform a physical open, or provide VFS authority.

## Canceling a pending handle

`release_pending_replay.hepta` reuses the same three-row logical state
checks as close/collect but withdraws a positive pending count and leaves
actual handles unchanged. Its input extends the 240-byte close packet by
one u64 action: 1 for `unpublished-actual-close`, 2 for
`failed-open-no-methods`. The 112-byte output uses the same accounting
layout and appends the actual cleanup action. A main pending withdrawal
decrements the root count before collection. Actual handles, SHM and
unbound reservations block a refund. A second main generation can defer
the old generation's refund. Both original growth policies and both
cleanup actions are compared against the unchanged Rust ledger, including
original cleanup after an earlier open failure. This private observation
does not open or close a file, certify any existing sticky failure, or
model a cleanup event that would itself fail to serialize.

## Shared memory reference accounting

`shm_replay.hepta` replays original logical shared-memory references, not
a memory map or VFS operation. Its 280-byte packet extends the three-slot
close/collect input with action (1 add, 2 close), ordinary event count,
denial count, sticky reason and first SQLite code. The 144-byte output
contains active-main count, cleanup length, retained slot bitmap and
logical charge, chosen row, ordinary length, denials, first error and
original event tag. The active-main count does not change on either action.

An add does not repeat ordinary admission. It checks the 32-reference
limit before the evidence limit; with 32 existing references and 1,024
ordinary events, the original reference-limit failure wins. A close,
including a saturating close at zero, appends the scoped cleanup event
then sweeps the three slots. A linked slot, another retained root
generation, a pending open, or actual handles can prevent release.
Tests run original V1/V2 ledger methods to reach both full conditions
and the final successful cleanup event. Event serialization failure,
real SHM mappings, and production ownership remain outside this mode.

## Retention of a measured event

`record_evidence.hepta` models the original recorder after the caller
has measured one actual compact JSON event. The 80-byte input includes
class (1 ordinary, 2 cleanup), measured byte count, both vector counts,
next sequence, retained byte total, completeness, denial count and first
error. The 72-byte output carries both counts, sequence, total,
completeness, denials, first error and whether the event was retained.
Reason 1 represents recorder pressure and reason 2 represents some
earlier original failure.

Exactly 512 bytes fit. The ordinary and cleanup vectors have independent
1,024 and 256 record limits. Pressure is SQLite FULL and does not consume
sequence or retained bytes; it marks incomplete evidence, increments
denials and preserves the first failure. An event in the other class can
still be retained without clearing the incomplete flag. Tests use the
unchanged Rust recorder and real compact JSON byte lengths, including
escaping and non-ASCII content. Native serialization, live vectors,
underlying operation mutations, and unreachable sequence overflow remain
outside this finite comparison.

## Compact lifecycle event byte measurement

`lifecycle_json_size.hepta` measures the original compact
`serde_json::to_vec(LifecycleReceipt)` length without emitting JSON. Its
104-byte fixed prefix contains, in order, the action tag, sequence,
generation, device, inode, linked bit, actual handles, pending opens,
SHM references, high-water bytes, actual bytes, requested endpoint and
option bits. Each field is little-endian u64; the three reference counts
must fit u32. Bits 0, 1 and 2 denote device, inode and endpoint presence,
respectively; an absent payload must be zero. The remaining 0–512 bytes
are one valid UTF-8 basename. The 8-byte output is the number of bytes,
including results above 512; retention is a separate decision.

The twelve fixture action tags are original retained literals, ordered
as reserve-open, bind-existing-before-io-v2, bind-real-inode,
reserve-growth, reserve-handle, opened, unpublished-actual-close,
failed-open-no-methods, shm-reference, underlying-close,
underlying-shm-unmap and unlinked. Device and inode None each serialize
as null. Endpoint None omits its key; Some(0) includes it. Shared HIA
UTF-8, escape and unsigned-decimal helpers measure compact widths. The
Rust differential includes actual V1/V2 ledger receipts and actual
cleanup retention at 511, 512 and 513 bytes, alongside separate typed
encoder fixtures for numeric, escaping, and option extremes. Neither
entry point creates a file, retains a record, or routes production VFS
work.

## Typed record and retention

`typed_record_evidence.hepta` runs both steps in one private native entry.
Its packet is the 104-byte typed receipt prefix, seven little-endian
u64 prior-state values (ordinary count, cleanup count, retained JSON
byte total, completeness, denial count, first reason, first SQLite code),
then the 0–512 byte UTF-8 basename. It has no measured-byte or class
field. The native measure supplies the former; the original action tag
determines the latter. The embedded event sequence is checked against
the sum of the prior vector counts.

The entry returns the existing 72-byte retention diagnostic. SQLite FULL
preserves sequence and retained total, and keeps any earlier error while reporting the
original evidence failure. Malformed or short packets publish no
diagnostic. Tests bind the exact original Rust recorder, including 511,
512 and 513 bytes in both classes, the 1,024 and 256 vector limits,
cross-class append, earlier error and all original action routes. This
does not verify externally provided ledger state, emit JSON, write a
vector, or own a production callback.

## Compact lifecycle event emission

`lifecycle_json_emit.hepta` accepts exactly the typed measurement packet.
It validates UTF-8 and measures the compact form with the existing
native helper before writing anything. If the caller supplies fewer
than eight bytes plus the exact JSON length, both mutable spans stay
untouched. Success writes an eight-byte little-endian length followed
by exact compact UTF-8 JSON in original Rust field order. It leaves the
output suffix and scratch unchanged. Malformed input returns 100;
insufficient output returns 102.

The original locked serde bytes are compared end to end across all
twelve action literals, V1/V2 original receipt paths, null versus zero
versus omitted options, escaped controls and punctuation, and UTF-8
through four-byte code points. Widths 511, 512 and 513 are emitted
without prejudging ledger retention. No event is appended by this
entry, and it does not own a filesystem or production VFS callback.

## Retained compact JSON in one transition

`retained_lifecycle_json.hepta` accepts the same typed receipt and prior
state packet as `typed_record_evidence.hepta`. One native call measures
the bytes, chooses the original vector by action, checks the sequence
and state bounds, and applies the existing retention predicate.

When retained, the output is the 72-byte diagnostic, an eight-byte
little-endian JSON length and exact compact bytes from the same input
receipt. If the entire successful output cannot fit, return 102 and
leave both mutable spans untouched. Original SQLite FULL publishes only
the 72-byte pressure diagnostic, even if more output is available.
Bytes at and beyond offset 72, including any stale caller-provided
length slot, are unchanged on pressure and must not be read as data
from this call. Malformed typed state is not reported as original pressure.

The comparison reserializes events actually retained by the locked
Rust ledger and checks their exact bytes and counters. It also checks
pressure, exact and short capacity and untouched suffixes. This is a
private bounded transition; it does not own live SQLite vectors or
route VFS callbacks.

## SHM references when recording cannot retain an event

`shm_record_replay.hepta` composes the original SHM logical mutation,
cleanup collection, record decision and exact compact event bytes. The
first 160 bytes match the typed retention prefix; the next words give
the selected slot and active main count, then the three nine-word
close/collect rows. One observed UTF-8 basename starts at offset 392.
The module derives the reference count and binds the typed prospective
event to the selected row before applying the measured retention step. Action 9
adds and action 11 closes; this slice covers existing slots and adds
with at most 31 prior references. The separate SHM replay already
covers the earlier reference limit at 32.

The output starts with the 72-byte retention diagnostic and then five
little-endian u64 words: selected reference count after mutation,
retained slot mask, logical charge, internal recorder status and active
main count. Only successful recording adds a length at offset 112 and
the exact JSON bytes at offset 120. Ordinary evidence pressure returns
SQLite FULL after incrementing the reference count. Cleanup evidence
pressure still sweeps all slots; the close returns success while its
explicit recorder status reports pressure. On pressure bytes beyond
the fixed 112-byte output stay untouched. Malformed and short output
cases publish nothing. The differential uses the original real ledger
operations under both policies, but does not map shared memory, write
vectors, own VFS callbacks, or inspect real files.

## Handle transitions when recording cannot retain an event

`handle_record_replay.hepta` uses the same typed receipt, prior evidence
and three ledger rows as SHM replay, with the observed basename at
offset 392. Action 6 transfers one positive pending open to actual
handles; action 10 closes one positive actual handle. The native entry
computes the two resulting counts, binds the prospective typed event
to the selected slot, and applies the original record limits.

The 120-byte fixed output is the 72-byte evidence diagnostic followed
by the new actual and pending counts, retained slot mask and charge,
recorder status and active main count. Only recorded success includes
a JSON length at offset 120 and exact original event bytes at offset
128. If the ordinary vector is full, opened returns SQLite FULL
after transferring its handle, preserving earlier failure evidence.
A close still decrements a main handle and sweeps all slots if the
cleanup vector is full; the outer return reflects the original unit
return while the recorder diagnostic retains SQLite FULL. Pressure
leaves the suffix untouched. Invalid or short packets write nothing.

Actual original V1 and V2 Ledger operations reproduce both cases and
successful controls on generated in-process fixtures. This does not
open or close a physical descriptor, own linked VFS vectors or change
the earlier admission checks.
