# History Startup wait and actual frontier follow-up

This isolated candidate follows the exact tree of PR [#535](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/535),
remote head `59e10da3f501970fff0a87ff398f8a08aa7fb59e`, tree
`4ee466caf266401c1ff72f8ac3fdf121f2020b33`. The local parent is the equal-tree
`c27c7201e700b6704faf3452da0921c7fedaa75a`. Its frozen source and evidence were not
edited. This is not a replacement for the parent's outstanding exact-source gate.

## Two concrete corrections

### Cold credit wait

Startup previously reserved its full allowance, then used `await_startup_credit`
which checked only its absolute deadline while earning the original two-second
burst at 0.25 CPU seconds per second. Cancellation and signed operation/budget
expiry were not observed during that approximately eight-second wait. A wait error
returned before the existing `not_started` branch and left a pending Startup.

The original wait API remains an adapter. The new callback entry checks the
original caller's cancellation and expiry between unchanged 50-millisecond sleeps,
outside the shared budget lock, and once more before returning ready. History
checks the same authority again immediately before `begin`. No new credit,
reservation, rate, ceiling or deadline is introduced.

If these checks fail before CPU `begin`, the caller appends the already-defined
NotStarted event with the original error. Replay keeps the entire four-second
predebit, operation ID, nonce and previously used epoch ID, clears the unstarted
pending scope/active epoch, and creates no CPU measurement or refund. This says
the paid CPU operation was never begun; it does not claim the waiting process used
zero physical CPU. Error during publication still fails closed under the retained
journal repair rules. Once `begin` exists, the original real settlement path remains
mandatory.

The new executable `wait::zero_credit_wait_interruptions_record_not_started_without_refund`
control checks an actual separate-thread cancellation, absolute deadline, signed
operation expiry, signed budget expiry and an interior callback refusal. It requires
the actual wait callback, no later material/Native phase, exact retained NotStarted
error, no settlement/clean-close event, unchanged full debit, cold journal replay,
nonce/epoch replay refusal, and ordinary fresh zero-credit Startup/paid Close/cold
readback. These new native cases have not been run locally.

### Known refusal with a wrong requested frontier

After an actual generation-one activation, a correctly signed operation can still
request a wrong old owner frontier. Native rejects it and records a known CPU
settlement with no effect marker. The previous recovery derivation selected that
last request's proposed frontier; the independent Native readback then rejected
the real generation-one store, making this valid refusal unrecoverable.

Replay now retains a private `epoch_frontier`, seeded at the original Startup and
advanced only by known settlements' retained actual SQL `marker.after`. A later
known refusal without a marker cannot change that frontier. It is derived from
the original frames and adds no field to a stored record or signed envelope.
Recovery still binds the last exact operation/intent, whole original journal
anchor, original marker or its absence, and independently checked Native frontier.

The existing `TRNM-HISTORY-SETTLED-EPOCH-RECOVERY-V1` domain, two signatures,
source/executable pins, fresh nonce/ID, additional full-dead-process allowance,
unchanged old debits, original lifetime ceiling and pinned publication wrapper
remain in force. This does not import the differently accounted KnownEpoch
Retirement protocol in [#532](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/532).

The executable `settled_epoch::known_wrong_frontier_refusal_keeps_actual_frontier_through_sigkill_and_recovery`
control adds a separate mode to the real source/binary-bound child guardian. It
first opens, validates and activates to generation one, then issues the wrong
frontier operation and requires its known refusal with no marker. It performs the
original pidfd/stop/four-snapshot/SIGKILL/wait4 observation. A newly signed receipt
that substitutes the rejected requested frontier must fail. The authentic receipt
must recover, preserve every old record and full debit, then allow ordinary fresh
Startup/validation/activation/paid Close at generation two and a final cold read.
The new mode requires nine total nonrefundable four-second reservations, including
the separate conservative process charge, with eight original known settlements.
Existing modes keep their original expected counts and assertions.

## Qualification and gates

Node compilation, strict Clippy, both new native controls and the complete
21 passed / 0 failed / 1 ignored native group are **NOT_RUN locally**. The shared
disk was below the existing 256 MiB compilation floor. No new target was built and
no cache was removed. Static/syntax and Python runner controls are separately
recorded in this directory; none substitutes for native execution.

The actual [static-01 terminal](static-01/terminal.json) records:

| Check | Actual result |
| --- | --- |
| Whole workspace Cargo formatting | PASS, Rust 1.95.0 / rustfmt 1.9.0, workspace edition 2021 |
| Exact native roster / owned-command / binary archive controls | 5 PASS |
| Retained guardian component controls | 4 PASS |
| Source-integrity negative controls | 34 PASS |
| Project-boundary negative controls | 16 PASS |
| Generated distributed source inventory | PASS |
| Locked offline Cargo metadata, no dependency build | 25 packages / 25 members, PASS |
| Source bytes before/after these checks | All 1,620 non-evidence files equal |
| Prior frozen #535 candidate bytes | All 72 manifest entries unchanged |
| New Node build / Clippy / native 21/0/1 | NOT_RUN |

Each command has its original full output in gzip, raw/compressed SHA-256, exit
status and actual duration. Before/after source inventories are retained. The
generated native source inventory also adds the parent's previously missing
`tests/startup.rs` entry and sorts the old `settled_epoch.rs` entry; no existing
entry is dropped. An initial exploratory direct rustfmt invocation selected
edition 2024 and reported formatting differences; it made no edits and is not a
workspace formatting verdict. The actual Cargo formatting above used the
repository's original edition 2021.

The same-source hosted runner retains all 15 original methods, all four Startup
methods and the existing explicitly ignored child helper, adding the two named
methods above. It still uses one complete prefix invocation, a 600-second native
bound, original two-second burst/four-second allowance and four complete snapshot
attempts. The exact 22-name roster and 21/0/1 terminal are required; the old 19/0/1
terminal cannot pass. Actual release ELF gzip parts and independent reconstruction,
the original guardian controls, nine material tests, formatting and strict Clippy
remain mandatory. Actual original #526 hosted success is retained only as evidence
for its own immutable source, not borrowed for this candidate.

## Deliberately unresolved states

- A real SIGKILL before a NotStarted record exists cannot be inferred to have
  occurred before CPU begin. The live refusal branch does not certify that window.
- Pending Startup after CPU begin, partial Native initialization, pending Close
  without a known settlement, torn/missing frames and partial multistep reorg
  still need distinct, externally bound recovery evidence and state contracts.
- An incorrect first Startup frontier is not promoted to an independently
  observed Native frontier. This correction covers an epoch with actual retained
  effect evidence followed by a refused request.
- Exhausted lifetime ceilings, arbitrary subprocess trees, physical power loss,
  production/public-service and full capacity qualification remain open.

## Parallel branch comparison

Read-only comparison used #528 head `65d59bb3ca2186810abce6a9be6535e2a5080b50`
and #532 head `e4880ba589c8a2a4cf65355acd4d1c1651824137`. #528 independently
repairs exact complete journal publication. #532's distinct KnownEpoch transcript
and no-extra-debit retirement cannot be silently substituted for this candidate's
conservative extra-charge contract. Its actual-marker-only frontier derivation
exposed the refusal issue addressed here; no sibling runtime source was merged.
Their reported execution outcomes were not requalified by this source review.
