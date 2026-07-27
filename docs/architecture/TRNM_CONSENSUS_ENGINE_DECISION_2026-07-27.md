# TRNM Consensus Engine Decision — 2026-07-27

Status: **Accepted direction; integration not yet complete**

## Decision

Do not extend the current loopback validator protocol into a bespoke public
testnet consensus engine. Keep the Rust application/state machine and finality
receipt format, but integrate a mature BFT consensus engine behind an explicit
adapter before any multi-host public testnet claim.

The implementation spike must compare an established Tendermint/HotStuff-family
engine with a Rust-native candidate using the same deterministic application
fixture. The default reference candidate is CometBFT through an application
boundary; a Rust-native candidate may replace it only if the spike proves the
same safety, recovery, observability, and operator lifecycle requirements.

## Why

The current live-devnet path now provides valuable application validity:

- validators receive complete command bodies;
- validators independently authenticate and execute commands;
- validators recompute transaction and state roots before voting;
- votes are durable and anti-equivocating;
- quorum is at least `2/3 + 1` voting power.

It still lacks the protocol surface required to call itself a multi-host BFT
consensus implementation: authenticated peer formation, proposer rotation,
round/view change, lock/unlock proofs, commit propagation, state sync, validator
set transitions, and adversarial network testing.

## Spike exit criteria

The selected engine must demonstrate all of the following with the canonical
`trnm-chain-node` application path:

1. deterministic proposal execution and application hash agreement;
2. four validators tolerating one Byzantine/offline validator;
3. crash recovery from proposal, vote, and commit boundaries;
4. partition healing without conflicting finalized heights;
5. validator join/rejoin through authenticated state sync;
6. stable metrics for height, round, peer state, vote power, and app latency;
7. reproducible deployment and rollback using no packaged private keys.

Until those criteria pass, `trnm-chain-validator` remains a
`loopback-local-devnet` validity/finality component, not a public-testnet
consensus engine.
