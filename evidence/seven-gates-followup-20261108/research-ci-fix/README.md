# Current process receipt gate and preserved research CI failures

All production, whole-chain PQ and real-loop qualifications remain **HOLD**.
This repair checks retained observations; it does not authenticate a receipt,
attest compilation, supply an independent review, or create a new proof.

## Original exact-source failure

The [original hosted run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015793)
tested Chain `bb026697a972521009bc133ae6ed2b653e18e931`, tree
`18175756871bf341586fc37be1b17a00ef1dd099`. Original before/after source records
are identical and retain 23,515 tracked entries / 2,382,494,143 bytes. The head
lane executed all 58 original saved-receipt controls successfully, then its
report gate failed with `process observation differs: schema`. The prospective
merge has the same recorded gate failure. The workflow remains **failure**.

The producer emits `TRNM-W1-STAGE-MEASUREMENT3`, including cancellation handoff
and deadline fields; the reader still demanded version 2. The [download record](transparent-bb-download.json)
binds artifact `13628437867` to its original 31,113,318-byte ZIP and SHA256. The
264,080-byte [selected archive](transparent-bb-controls.tar.xz), SHA256
`e5f2e58908889961a0198a273ea2c5aab0a70c679ea46c5b06d92a0012fab028`,
contains all 58 case directories, mutated inputs, process outputs, aggregate
records and source-after record. Separate original source/outcome files retain
the before/after records and native success followed by reader failure. These
bytes are not rewritten into a new native execution.

## Current and historical interpretation

| Path | Process schema | Required interpretation |
| --- | --- | --- |
| Current `validate()` and CLI | Version 3 only | Exact cancellation fields, original common deadline, full aggregate/case/process/input/output agreement |
| Explicit historical replay | Version 2 only with explicit recorded paths and selected historical schema | Saved-record consistency; no retroactive version-3 handoff semantics |
| Unknown or mixed version | Refused | No inferred migration or fallback |

Current records require cancellation fields to exist, no observed cancellation,
an unexpired deadline snapshot, and all original process/session settlement
checks. Stage clocks must be finite, positive, within the original 120 seconds,
and bound to the aggregate's unchanged absolute deadline. The aggregate's
elapsed time must cover each retained stage completion.

A stage result is explicitly a **pre-handoff snapshot**. It does not prove
`measure()` returned normally. The full runner must retain all 58 completed
controls with no error. A real-signal control calls the actual runner, observes
an exited `/usr/bin/true` process, and sends SIGTERM just after the stage result
is fsynced. This is a lifecycle refusal test; that executable cannot verify a
receipt. The saved stage remains exit zero, but the actual call is canceled,
the aggregate has zero completed controls and no positive report, and the gate
refuses it.

## Retained checks and limits

The original 23 named report controls remain. Eight additive controls produce
the current exact roster of 31: current process exits, legacy/unknown refusal,
missing/canceled fields, clocks, settlement, the exact hosted 58-case replay,
and real late cancellation. The workflow and literal CI contract require all
31 names exactly once, keeping all 58 native cases and their 120-second common
deadline. Both push and PR triggers include the new exact replay fixture.

The local 31-method campaign passed, all existing 151 CI-contract methods
passed, and the 16 affected workflow methods passed after the final trigger
addition. These receipts identify a dirty candidate, not a new committed-source
native campaign. The earlier 29-method campaign and its first two
missing-null-field errors remain separately retained. They exposed an existing
helper's `KeyError` when an expected-null field was absent; explicit key presence
now yields the intended refusal. Failed attempts are not counted as passes.

The [manifest](manifest.json) retains raw identities. Original implementation
mapping and closure failures are also retained as runs `42508015708` and
`42508015884`; their source-contract repairs are separate from this change.
Results for `bb026697` remain attached to that source after later commits.
