# Private HIA governance guard

`guard.hepta` implements the complete public local state machine of the retained
`trnm-governance-guard` crate. The native byte entry creates real private owners
for a complete typed command transcript, executes every role, proposal, bridge,
pause and audit operation in HIA, and drops all owners before returning. This is
component lifecycle qualification; incremental caller lifetime, authenticated
Node dispatch, durable storage and live governance integration remain separate
work. It does not provide a consensus authority or production deployment claim.

The public caller supplies methods and their typed arguments. It cannot supply
a mutable state arena, authorization boolean, proposal snapshot, bridge map,
nonce or version. The immutable captured strings, growing record arena and
unpublished response are native `buffer.try_new` allocations. Clone copies every
active record into its independent owner namespace; it shares only immutable
session string bytes. Drop clears that owner's records. Consuming audit clears
its event records and returns the original extra `AuditLogCleared` marker.

The borrowed scratch argument is unused. Any malformed input, invalid UTF-8,
insufficient output capacity or allocation refusal leaves output and scratch
unchanged. Allocation failures are tested by real `calloc` interposition, with
zero leaked owners and no invalid frees. No hosted governance implementation is
called by the native worker.

## Complete session ABI

`f0(readbuf input, mutbuf output, mutbuf scratch) -> u32` accepts `GVS10001`:
32 byte header (magic, command count, two zero words), then command frames of
96 bytes followed by five UTF-8 strings. All integers are little endian u64.
The frame words are operation, handle, proposal ID, eta, now, flags, caller
length, A length, B length, C length, D length and a zero word. Unused arguments
must be zero or empty. Strings are opaque, including empty strings, NUL and
Unicode whitespace; they are never trimmed or normalized.

| Operation | Method | Arguments |
|---:|---|---|
| 0 | new | handle 0, caller admin, A guardian, eta minimum delay |
| 1 | set_role | caller admin, A subject, flags proposer bit 0 / executor bit 1 |
| 2 | set_guardian | caller admin, A subject, flags enabled 0 or 1 |
| 3 | set_allowed_param_key | caller admin, A key, flags enabled 0 or 1 |
| 4 | propose | caller proposer, A key, B old, C new, D reason, eta, now |
| 5 | queue | caller proposer, proposal ID |
| 6 | execute | caller executor, proposal ID, now |
| 7 | cancel | caller, proposal ID |
| 8 | emergency_pause | caller guardian, A reason |
| 9 | schedule_unpause | caller guardian, A reason, eta, now |
| 10 | execute_unpause | caller executor, proposal ID, now |
| 11 | proposal | proposal ID |
| 12 | bridge_state | none |
| 13 | audit_log | none |
| 14 | consume_audit_log | none |
| 15 | normalized_audit_log | none |
| 16 | clone | source handle |
| 17 | drop | source handle |

The `GVR10001` response has a 32 byte header (magic, command count, exact used
bytes, zero). Each reply contains four words: operation, original handle,
method status, payload size; payload follows. New and Clone return a new handle
word, propose and schedule return a proposal ID word. Handles are session local
selectors; authorization still requires the exact original caller string.

Method errors 1–16 follow the original `Error` declaration order; 64 is an absent
or dropped session handle. Outer return codes are 0 complete success, 1 malformed
typed frame, 2 invalid UTF-8, 3 insufficient output, 4 allocation/capacity refusal.
Method errors remain ordinary replies and do not terminate the transcript.

Proposal payloads use a presence word; absent is exactly eight bytes. Present
proposals have a 128 byte header: presence, ID, kind, status, eta, base version
presence/value, executed-at presence/value, executor presence, then six lengths
for proposer, executor, key, old value, new value and reason. Those strings follow.
Kinds are ParamChange=0 / EmergencyUnpause=1; statuses Pending=0, Queued=1,
Executed=2, Cancelled=3. Option None and Some(empty or zero) stay distinct.

Bridge payloads contain paused, value-map count and version-map count. Maps sort
by exact UTF-8 key bytes. Each value row has key/value lengths and bytes; each
version row has key length, version and key bytes. The real pause flag remains
separate from any ordinary parameter whose string key is `emergency_pause`.

Audit payloads start with an event count. Each raw event has 18 header words:
variant, proposal ID, proposal kind, key/old/new presence, version-before
presence/value, version-after presence/value, eta, previous/next pause flags,
and actor/key/old/new/reason lengths. The five strings follow. Inapplicable words
are zero. Variant order follows the original enum, 0 through 7. Normalized audit
uses the existing `NAER0001` encoding with its 96 byte header, option mask, full
u128 amount and seven strings. All event ordering, formatting, empty options
and current proposal context are retained.

The public entry never accepts test state injection. A separately built fixed
qualification fixture exercises private counter exhaustion and deliberately
seeded internal drift using the same production HIA methods. Its artifact is
not the public owner artifact. The unchanged original crate's 45 retained tests
also run directly under rustc, alongside exact public transcript comparisons.

`TRNM_HIA_GOVERNANCE_OUTPUT` selects a new evidence directory for the unittest
suite. Raw inputs, original output, native output, compiler bindings, retained
tests and stage logs are persisted. Final PASS requires the entire actual test
roster, no errors, unchanged bound source, and finalized reporting; a partial
run remains INCOMPLETE. No whole-chain or old-source retirement acceptance is
claimed by this component report.
