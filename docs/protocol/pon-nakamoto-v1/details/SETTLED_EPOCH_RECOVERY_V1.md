# Explicit settled-epoch recovery V1

This opt-in local research API closes an actually dead History epoch whose last
operation already has a known durable settlement, but whose process died before
`CleanClose`. It leaves the complete original V6 journal, charges and receipts in
place. It never turns a pending operation into a known settlement, repeats a
native effect, or claims that an administrative process paid the dead process's
CPU.

## Fresh authority and storage namespace

The signature domain is `TRNM-HISTORY-SETTLED-EPOCH-RECOVERY-V1`, followed by byte
`E`, role byte 1 or 2, a little-endian u32 canonical body length, and the canonical
JSON body. Registry and task keys remain distinct and both signatures are required.
The new authorization names the exact identity, budget ID, reconciliation ID,
nonce, epoch, externally pinned journal anchor, last settled operation and intent,
dead-process receipt digest, native frontier, finite allowance and current time
window. It also names the executable SHA-256.

The bounded protected input separately pins `expected_source_commit` and
`expected_executable_sha256`. The source pin must equal the identity's source
commit, and the binary pin must equal both the signed authorization and the exact
closed-process receipt. A newly signed receipt for a different binary cannot
silently select its own accepted executable. The protected input is an outside
trust input; parsing a local process report does not establish those pins.

The new event is `settled-epoch-reconciled-v1` inside a frame with the distinct
schema `restricted-history-settled-epoch-record-v1`. Original V6 events retain
their original schema and meaning. Replay requires the event and record schema
to agree; a new transition cannot be relabeled as an old V6 record. Old readers
that do not implement the new namespace reject it rather than reinterpret it.

## Conservative accounting and expired budgets

The replayed state must have no pending operation, a live epoch identifier, and a
last known settlement matching the receipt's operation, intent, marker and native
frontier. The full original allowances remain spent and all original receipts
remain unchanged. A fresh reconciliation ID and increasing nonce consume one more
operation and a separately signed CPU allowance from the same lifetime ceiling.
That allowance must cover the **entire dead process's** conservative wait4 CPU
upper bound. It is deliberately additional to the old charges. The API makes no
claim to know the residual CPU split or to have prepaid an unobserved interval.

This fresh domain authorizes only post-exit accounting and epoch closure. It may
be used after the old budget expires, but it cannot increase that budget's
lifetime ceiling, change its nonce range, grant a Startup, or revive any old
effect permission. The new authorization itself must be current. After closure,
an expired old budget still refuses Startup. A separately signed ordinary Budget
update is required before a fresh zero-credit epoch can start. A lifetime ceiling
with no room for the conservative extra debit remains an explicit refusal; this
API has no implicit credit or quota expansion.

## Native state and process boundaries

The original process must be actually closed under the existing source-bound
native thread-only receipt profile, including pidfd identity, owned PID, visible
PID/start time, actual SIGKILL/wait4 and quantized user/system counters. This
profile is not arbitrary subprocess-tree adoption and does not certify physical
power-loss behavior.

The API opens an existing journal and owner lock without creating either. It also
holds the native owner lock, exact directory, SQLite file and owner marker through
the read-only native transaction and the append. It verifies the V6 schema,
parameters, genesis, owner marker, active frontier and every known effect marker.
Pending reorganization is refused. Before append, it rechecks held versus visible
directory, owner lock, SQLite and marker identities and rereads the marker bytes.
No new CPU epoch or native Node is constructed by reconciliation.

The only new state transition is the fresh, fully signed additional debit and
termination of the named dead epoch. Repeating the original request after the
journal advances is rejected without another debit. The explicit pinned publication wrapper can complete one exact new-namespace
frame after a crash. It requires both the original protected recovery input and a
fresh publication authorization, checks the exact signed/closed bytes and the
independent source/binary pins, and holds the same read-only native validation
through publication. The generic V6 repair rejects a new epoch transition. The
original event is authenticated at its recorded `frame.at_ns`; the new publication
authorization must be current. Expiry cannot turn an existing complete frame into
new running authority, and missing/partial bytes are never reconstructed.

## Native qualification scope

The source includes real process controls for a fully settled activation killed
before clean close, each of the five publication cuts of the new reconciliation
record, and an actually expired old budget followed by fresh closure and separate
renewal. The publication tests additionally kill administrative repair processes
after linking and unlinking the pending alias. Their wait4 records never become
receipts for the original native epoch. Every successful sequence must continue
in a new process through zero-credit Startup, full W1 validation, two joined M06
workers, activation, paid close and cold journal/native readback.

The executed results, source and binary hashes, retained failed attempts, and
adversarial controls are in the
[native evidence](../../../../evidence/pon-history-publication-native-20261028/README.md).
Neither these controls nor the new API close all History P0 requirements.
Unresolved Startup/Close operations, signed multistep reorg continuation,
arbitrary process trees, partial-frame reconstruction, physical power loss and
whole-host resource qualification remain separate work.
