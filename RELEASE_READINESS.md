# TRNM Release Readiness

Updated: 2026-09-07

## Current conclusion

**Not release-ready. Do not claim public-testnet or public-mainnet readiness.**

## Binding architecture

The sole consensus route is the native self-developed Rust stack:

```text
trnm-chain-node
  -> native proposal, vote, quorum, and round-change protocol
  -> trnm-chain-validator verification and durable anti-equivocation
  -> deterministic state transition
  -> committed state, receipts, and AppHash
```

External consensus engines and adapters are outside project scope. Historical experiments using an external engine have been removed from code, dependencies, CI, scripts, runbooks, release documents, and active architecture records.

## What currently exists

- native node, validator, CLI, and deterministic simulation binaries;
- signed consensus messages and durable anti-equivocation state;
- quorum-based local BFT fixtures;
- restart, replay, message-authentication, round-change, and fault-matrix gates;
- state, executor, mempool, RPC, worker, oracle, bridge research, proof, and finality-support crates;
- local release and evidence tooling.

## P0 blockers

1. **Consensus specification and proof boundary** — freeze the formal state machine for proposal, prevote/vote, lock, unlock, round change, commit, and validator-set transitions; document safety and liveness assumptions.
2. **Authenticated multi-host network** — complete peer identity, secure transport, discovery/bootstrap, scoring, backpressure, abuse handling, and remote join/rejoin.
3. **State sync and recovery** — provide authenticated snapshots/checkpoints, fast catch-up, corrupt-input rejection, crash consistency, and multi-host recovery evidence.
4. **Validator lifecycle and economic security** — close genesis ceremony, admission, voting power, rotation, removal, unbonding, jail, slashing, and disaster recovery.
5. **Secure signer path** — integrate HSM/KMS or remote signing, key rotation, compromise recovery, and double-sign prevention under operator error.
6. **Governance** — require threshold authorization, timelock, cancellation, emergency pause, upgrade discipline, and auditable parameter changes.
7. **Performance evidence** — publish sustained finalized TPS and P50/P95/P99 finality from multi-host tests, including resource use, state growth, conflict profiles, failure periods, and raw logs.
8. **Security assurance** — enable a verified private reporting route, complete independent audits, long fuzz campaigns, supply-chain provenance, and incident drills.
9. **Production read surface** — close durable indexer, explorer/API, historical queries, retention, and archive strategy.
10. **Economics and anti-spam** — freeze fee/admission, sponsor, rate-limit, storage pricing, and resource-abuse boundaries.

## Evidence rules

- A simulation or single-host run is never network-readiness evidence.
- Submission rate is not finalized TPS.
- A test for one binary does not prove a capability in another binary.
- Every result must identify the exact commit, configuration, workload, topology, hardware, observation window, and finality definition.
- Any state-root divergence, double-sign condition, non-contiguous recovery, or unauthorized validator transition is an immediate NO-GO.

## Truth-source hierarchy

1. `RELEASE_READINESS.md` — current release decision.
2. `docs/architecture/TRNM_SELF_DEVELOPED_CONSENSUS_CANONICAL_2026-09-07.md` — binding consensus architecture.
3. `OPERATIONS.md` — current operating procedure.
4. `SECURITY.md` — supported security scope and reporting policy.
5. Date-stamped reports — evidence for their exact commit only, never automatic current truth.
