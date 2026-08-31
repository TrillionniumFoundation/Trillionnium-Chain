# trnm-consensus-sim

Deterministic, in-memory fault simulator for the current epoch-0 PoCO-BFT core
prototype. It drives `Effect`/`Input` boundaries without opening sockets,
starting services, reading a wall clock, writing a database, or owning a real
signing key.

This crate is **not wire-conforming yet**. Its bootstrap now uses the exact
trusted, empty-signature `GenesisQcV0` path with
`synthetic_genesis_block_id = genesis_hash`; an ordinary signed view-0 QC is
rejected.

Finalization now carries and verifies the frozen `FinalityProofV0`, retaining
each signed proposal's exact justification and optional TC. Epoch-anchor and
handoff finality remain unavailable because the epoch-transition state machine
is still fail-closed and unimplemented.

The simulator is also epoch-0 only. Epoch transitions, a rollback-resistant
sign journal/remote-signer watermark, authenticated networking, durable WAL,
and real runtime execution remain outside this crate.

`Trace` is a deterministic diagnostic transcript, not yet a self-contained
replay input format. Scenario code must still recreate the configuration and
external fault actions. Trace entries retain full object identifiers,
signatures, signing roots, and safety-state digests so repeated-run comparison
does not rely on display prefixes, but a canonical trace decoder/replay API
remains a P1 blocker.

## Current regression evidence

As of 2026-08-12, the crate contains 32 tests: 16 focused unit tests and 16
deterministic scenarios. They cover applied-chain prefix comparison, key-bound
mock signatures, 4-/7-validator quorum-loss boundaries, 2+2 partition/heal,
persistence-before-sign rollback, durable conflicting-QC halt/restart,
consumed drop/duplicate/delay/reorder faults, and a running crash from nonzero
durable state through safety replay and synced-payload validation. Scripted
payload callbacks additionally cover `Unavailable -> Valid` with a fresh
generation, certified deterministic invalidity that remains halted after
recovery, replay which waits for `Valid` before completing, and a wrong-block
candidate that the simulated application boundary rejects before sealing. The
old generation is consumed as `Unavailable`; only a fresh Core request can
later accept the exact candidate. A standalone
QC-before-proposal scenario proves that the exact catch-up obligation is
persisted before requesting data, survives a crash immediately after the
durable acknowledgement releases the request, is reissued with the same
certificate ID, and clears durably only after its exact target passes synced
validation. Replay continuations and synced-validation callbacks are bound to
a request generation, so an old active target cannot drive or complete a
rotated backlog/TC request. The driver cancels only the exact old volatile core
obligation; an unknown generation is rejected before the core's busy gates and
transactional clone. If a replacement request still requires the same
in-flight ancestor, the stale result is discarded and exactly one fresh
callback is rebound to the new generation without consuming the stale event's
fault outcome. Focused tests begin from a real
`SyncedProposal -> PersistAck -> ValidateSyncedPayload` obligation and cover
both callback-first and replacement-`ReplayNext`-first orderings through
fresh-ID completion and replay cleanup. A second catch-up scenario drops both the parent
proposal and its direct QC, proving that a later proposal carrying that exact
justify QC creates the same persist-before-request obligation and recovers the
same certificate/target after a crash. Finalized-height certificate injection
also freezes the stale-QC split: a different-view competing block is
historically subsumed without replay or safety-state mutation, while a
same-view competing block becomes a durable conflicting-QC halt.
An additional short-epoch campaign reaches the last ordinary height, then
proves the epoch-boundary fence rejects every regular checkpoint proposal
without emitting a checkpoint vote or forming a checkpoint QC; post-rejection
scheduling remains safe and bounded.

Progress assertions use applied finality plus a durable cleared-outbox
watermark; they do not treat a volatile in-core finalized tip as completed
application finality. The safety oracle now compares every observable finality
layer after each deterministic event and before a run/crash/recovery step:
online core state, acknowledged durable state, current-incarnation pending
`PersistSafetyState` effects, durable and queued `Finalize` proofs,
application-acknowledged chains, and the durable application-ack watermark.
Every pair must be prefix-comparable, and a malformed/incomplete observation
fails the run instead of being omitted. Focused tests prove that pending effects
enter the oracle and that an injected application/core fork is rejected before
another event executes.

For nonzero core/storage/proof tips, the oracle reconstructs ancestry from the
simulator's global in-memory proposal archive. That is sufficient to detect a
simulated cross-layer fork, but it is not evidence that a real node can recover
the ancestry from its WAL/state-sync store. Stale queued effects from a crashed
incarnation are deliberately excluded because the simulator will never apply
them; their last acknowledged durable state remains covered. Corrupt WAL
bytes, external application rollback, and independent state-sync responses
still require P2 fault surfaces.

Every simulator-created proposal now retains a canonical
`ApplicationPayloadV0`, deterministic receipt commitments, and empty ordered
evidence, then mints `ValidatedBlockCommitmentsV0` through the real B2-D body
kernel before returning `Valid`. Each live Core immediately issues one
process-local application-seal authority to its private development-only
simulated host. Every `Validate*` effect is uniquely claimed; its non-cloneable
permit and later application-sealed proof remain in `SimNode`, never in the
cloneable event queue or trace. A crash/recovery drops all old capabilities and
installs the recovered Core's fresh authority. This exercises the real opaque
Valid callback gate without adding a public Core bypass. It is not a durable
ApplicationStore. Finalization follows the same process-local boundary: each
live Core issues one application-finalization apply authority, while the
cloneable event carries only the inert authenticated queue-front projection.
The private simulated application consumes the exact one-shot front permit,
derives a deterministic inert readback projection from the exact queue carrier
and its durable Valid source, then consumes both permit and projection into the
non-cloneable receipt. The projection is retained beside that receipt across
Busy/rejected callbacks, and the unique receipt retries only against its
issuing Core. Public clones and foreign authorities are rejected even when
their durable carrier bytes agree; a successful queue pop rotates the front
permit while retaining the installed application authority.
Crash, recovery, and safety halt discard every old authority and receipt, and
recovery installs fresh authorities from the authenticated recovered Core.
This is still not durable ApplicationStore evidence: cross-crash Valid permit
remint, SafetyStore readback, `StorageAck`, application
acknowledgement/retirement, alternate body sources, authenticated parent state,
authorized-runtime execution, and receipt provenance remain outside the
simulator. Its row-like readback checksums are domain-separated in-memory
comparison bytes, not SQLite/JMT receipt rows. The finalization apply/readback
stand-in therefore does not prove the production ordered apply transaction,
source binding, exact durable readback, or cross-store recovery matrix.
Additional P1 blockers remain: all simulated
validators currently have equal weight; recovery and TC aggregation and
standalone-QC catch-up use global in-memory object availability; the complete
persist/sign/broadcast crash matrix is absent; and no stale-disk/signer,
epoch-transition, or heterogeneous-certificate campaign exists. The key-aware
deterministic signature scheme is test-only and is not Ed25519 or
authenticated-network evidence.
