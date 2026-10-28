# Explicit History journal publication repair V1

This local research API repairs publication of **one complete, existing V6 journal
frame**. It does not change V6 signatures, events, native SQLite schema, CPU
settlement or ordinary open behavior. It does not authorize a reorganization,
release an unresolved operation, manufacture a clean close, or activate a service.
The exact implementation and executed observations are recorded in the
[increment evidence](../../../../evidence/pon-history-publication-repair-20261027/README.md).

## Outside authorization

The fresh signature domain is `TRNM-HISTORY-JOURNAL-PUBLICATION-REPAIR-V1`, followed
by message byte `P`, signature-role byte 1 or 2, little-endian u32 canonical body
length, and the serde-encoded body. Registry and task keys are distinct, pinned by
the protected local input and the unchanged V6 identity. Both signatures are
required. The body schema is
`restricted-history-journal-publication-authorization-v1`.

The body names the exact identity, acknowledged prefix anchor, next published
anchor, frame SHA-256 and byte length, and a finite issued/expiry window. The next
sequence must be exactly prefix sequence plus one. Its digest must equal the exact
frame digest. The independently supplied `outside_latest_anchor` in the protected
input must equal this published anchor. A disk-derived candidate or an observer's
barrier record is evidence for the external authorities to inspect; neither is an
automatically approved latest anchor. A stale input cannot silently promote a tail.

The protected file uses the existing bounded ownership, private-mode, no-follow,
single-link and whole-file digest checks. The API opens an existing journal and
existing lock without creating either. The original exclusive journal lock fences
other cooperating owners for the complete operation.

## Exact-byte repair

The repair accepts only the complete earlier canonical prefix, plus exactly one
selected tail represented as either its temporary `pending-N` name, its canonical
final name, or both names as the **same physical inode with exactly two links**.
Unrelated names, extra links, two independent files with equal contents, unsafe
permissions, symlinks, missing prefix and different bytes are refused without
removing their evidence.

It replays every original prefix event and the complete candidate through the
unchanged V6 journal state machine. Original grant signatures, nonces, lifetime
ceilings, full allowance predebits, marker checks and settlement conditions remain.
A repair signature over an invalid original event cannot turn that event valid.
Partial bytes are not reconstructed from a guessed intended frame. No content is
truncated, overwritten, or discarded to make a journal pass.

After validating exact state and physical identities, it fsyncs the held complete
frame, links the final name without replacement if needed, fsyncs the directory,
removes only the verified alias of that same inode, fsyncs the directory again,
and performs exact final-byte readback with one remaining link. A crash during
these operations leaves one of the same explicit repair shapes. Repeating the
same authorized repair against that exact final frontier is idempotent: no new
journal event, operation, allowance, CPU receipt or epoch appears. Once later
frames exist, this old request cannot rewind them.

## Recovery remains a separate operation

Publishing an Intent preserves its complete original predebit and unresolved
operation, including the unknown CPU split. Normal startup still cannot skip that
debt. The existing independent V6 process reconciliation requires real closed-
process evidence, both authority signatures, exact native frontier/marker readback
and a conservative whole-process CPU bound within the original operation's
allowance. Only a subsequent fresh startup claim starts a zero-credit epoch.

The new native process controls target the five original publication boundaries:
after complete file fsync, after linking the final name, after final-name directory
fsync, after removing the pending alias, and after final directory fsync but before
local state application/return. They use a validation Intent, actual SIGKILL/wait4,
outside publication authorization, unchanged V6 debt reconciliation, a new process,
full W1, two joined M06 children, activation, paid close and cold readback. The
native callback exists only in Linux test builds and selects an exact barrier; it
does not change production publication steps or act as the outside authority.
The pending-file case additionally kills two fresh administrative repair processes
after the repair links the final name and after it removes the pending alias.
The same authorization then completes idempotently; those administrative wait4
observations never become V6 original-operation CPU recovery receipts.

## Remaining limits

This repair cannot reconstruct a partially written frame or a missing externally
pinned frame. It does not by itself close startup/clean-close crashes, an epoch
whose last settlement completed before an unclean exit, SQLite write cuts or
signed multi-step ReorgContinuation. Arbitrary historical subprocess adoption and
physical power loss remain outside the source-bound thread-only process profile.
Its finite control-plane metadata reads and signatures are not a physical resource
or whole History P0 qualification. Exact native verdicts, source/binary pins and
retained failures belong to the increment evidence, not this protocol description.
