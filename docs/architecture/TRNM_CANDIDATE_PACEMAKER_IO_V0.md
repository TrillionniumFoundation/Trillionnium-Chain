# Candidate Pacemaker I/O v0

Status: feature-gated candidate; no production or consensus activation authority.

## Boundary

`trnm-poco-node-io` retains an entirely inert default build. The optional `candidate-pacemaker` feature adds a polling-only timer mechanism and does not create a thread, socket, Proposal, Vote, Timeout, QC, TC or finality effect.

Each arm is bound to an exact `(epoch, view, generation)` identity and an absolute monotonic deadline. The candidate enforces a 60-second local horizon, exact same-arm replay, monotonic arm ordering and one outstanding effect. A fired timer repeats unchanged until exact acknowledgement, preventing response loss from silently consuming the effect. A conflicting same-identity deadline, stale/reordered arm, wrong acknowledgement or attempt to rearm with an unacknowledged fire fails closed.

Any observed clock regression poisons the object, clears pending local authority and requires replacement/recovery. The candidate does not persist the clock generation or timer state; production restart recovery must bind those facts to an authenticated durable owner.

The identity admits epoch `0`, the initial PoCO-BFT epoch. Ordinary views and local generations MUST be greater than `0`; the synthetic view-zero genesis anchor cannot arm a timer. An epoch in a timer identity does not authenticate an epoch transition. That remains the consensus owner's responsibility. `initial_protocol_epoch_can_fire_and_advance_but_genesis_view_cannot_arm` covers the epoch-zero fire/ack/next-view sequence and rejects view-zero or generation-zero identities; it is a source regression, not durable timer recovery evidence.

## Non-claims

This mechanism does not establish:

- a production monotonic clock or suspend/resume behavior;
- durable timer recovery across process or host restart;
- authenticated P2P or consensus effect routing;
- protocol timeout values or liveness performance;
- Proposal/Vote/Timeout, Safety, signer, finality or checkpoint authority;
- multi-host campaign, audit, soak or activation evidence.

## Required integration

A live candidate must couple fired timer acknowledgement to a durable, exact authority-session effect. It must recover any unacknowledged timer from authenticated persistent state, reject generation rollback, and exercise delayed/reordered messages, partitions, leader crashes, clock anomalies, process termination and host restart. Fixed-toolchain tests, strict Clippy, source-bound dependency closure and independent M03/M15/security review are mandatory.
