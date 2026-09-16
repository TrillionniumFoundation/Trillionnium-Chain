# P0 runtime blocker register

This register tracks blockers that cannot be closed by a documentation or
metadata change.  A blocker is closed only when the listed executable test
passes against the production-shaped owner, with durable artefacts retained
for independent replay.

## P0.1 persistent seven-validator network

**Current state:** open. `trnm-poco-lab-validator` starts one owner thread and
uses `network.rs`/`consensus_mesh.rs` for authenticated TCP sessions and relay
frames. The mesh does not start seven validator processes, own seven independent
SafetyStores, or reconnect consensus state across process boundaries. The
production host remains inert (`trnm-poco-node-host/src/facade.rs` and
`trnm-poco-node-io/src/lib.rs`).

**Required implementation:** a launcher that creates seven isolated validator
processes, each with a unique validator identity and non-overlapping durable
roots; authenticated consensus transport must deliver Proposal/Vote/Timeout/
QC/TC frames to the local Core owner; a process restart must reopen its own
SafetyStore and signer journal before accepting traffic.

**Acceptance command:** run a seven-process campaign from a clean run root,
kill one process, restart it, and verify that all seven signed event journals
and the final SafetyState records independently verify against the same
validator-set and run manifest.

## P0.2 two epoch transitions

**Current state:** open. `trnm-consensus-core/src/core.rs` rejects every
validator set whose epoch is non-zero and rejects heights at or beyond the
checkpoint. `safety_state_record.rs` only encodes epoch zero and rejects epoch
anchors. The cryptographic checkpoint/handoff helpers verify evidence but do not
activate Core, signer state, or durable epoch state.

**Required implementation:** atomically persist and recover checkpoint, seal,
handoff, coordinate binding, validator-set commitment, and next-epoch
parameters; admit the first block of the new epoch only after the complete
preimage and parent proof verify; repeat the same path for a second transition.

**Acceptance command:** produce two real epoch transitions in the seven-process
campaign, stop and restart at each stable cut, then replay all transition
records with an independent verifier. Any `UnsupportedEpoch`,
`EpochBoundaryUnsupported`, or `UnsupportedEpochAnchor` result is a failure.

## P0.3 signer device and anti-rollback anchor

**Current state:** open. Remote signer, external monotonic watermark, HSM and
whole-authority rollback flags remain false. Existing local journal checks only
relate the signer journal to the SafetyStore in one process; they do not prove a
hardware-backed monotonic value survives power loss or storage rollback.

**Required implementation:** bind Vote/TimeoutVote/epoch-seal signing to an
external signer, persist a monotonic counter or equivalent device anchor, and
make the startup gate compare the device value with the authenticated durable
SafetyState before any signing operation.

**Acceptance command:** inject power-loss and stale-snapshot faults, then prove
that the restarted node refuses old witness replay and refuses to sign when the
device watermark is behind or ahead of the durable state.

## P0.4 finalized goodput

**Current state:** open. Existing worker and MVCC benchmarks are speculative or
single-process measurements. They do not establish finalized, replay-verified
transactions across the network.

**Required implementation:** timestamp transaction admission, finality, and
replay verification in the seven-process runtime; report finalized goodput and
p50/p95/p99 latency with dropped, retried, and speculative work excluded.

**Acceptance command:** replay the signed final-state and event journals with an
independent verifier and recompute the latency quantiles and goodput from the
finalized transaction set.

## Cross-cutting dead code gate

`trnm-poco-node` contains 84 `cfg(any())` items. Several permanently disabled
modules include `process_host`, authenticated-genesis commissioning, and
recovery wiring. They must not be counted as implemented. Before enabling any
of them, compile the feature in CI and run the focused tests; deleting or
rewriting the guard without that build is unsafe.

## Closure rule

Changing a `production_*` constant, a Cargo metadata flag, or a document status
does not close a blocker. Closure requires a real runtime artefact and an
independent verifier for the acceptance command above.
