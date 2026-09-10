# TRNM Release Readiness

Updated: 2026-09-11  
Truth source: this file, bound to the exact assessed commit

## Current conclusion

**Not release-ready. Do not claim public-testnet or mainnet readiness.**

## Binding architecture direction

TRNM uses its self-developed PoCO consensus and settlement stack. The active implementation boundary is the native Rust workspace built from:

```text
trnm-node
  -> native validator quorum and finality
  -> trnm-state / trnm-pouw
  -> state roots, events, and finality receipts
```

Third-party block-consensus integration is not part of the production candidate.

## Existing development evidence

The repository contains meaningful local evidence for:

- signed command validation and replay protection;
- independent validator execution and root recomputation;
- `2/3 + 1` quorum handling in the native validator path;
- durable vote and state records;
- local restart, replay, rollback, and recovery drills;
- state-root and finality-receipt verification;
- PoCO task create, commit, reveal, challenge, resolve, timeout, and settlement paths;
- mempool admission, conflict grouping, backpressure, RPC, worker-agent, and CLI tests;
- local benchmark and fault-injection tooling.

This evidence is development evidence. It is not a substitute for a geographically distributed, adversarial, long-running public-network test.

## Release blockers

The following remain release blockers until closed by reproducible native-path evidence:

1. authenticated multi-host peer formation, discovery, scoring, and abuse handling;
2. validator onboarding, replacement, rotation, exit, and disaster-recovery ceremonies;
3. remote signing, HSM/KMS integration, double-sign protection, and key-compromise response;
4. protocol-level staking, unbonding, jail, slashing, and evidence handling where required by the launch model;
5. deterministic validator-set transition and upgrade governance;
6. state synchronization and fast catch-up under large historical state;
7. durable indexer, explorer, archive, and historical query services;
8. unified metrics, alerting, incident response, replay, and rollback evidence;
9. frozen fee, anti-spam, free-ingress, sponsor, storage, and retention policy;
10. multi-host throughput/finality benchmarks with P50/P95/P99 latency and sustained-load windows;
11. disk-full, OOM, clock-skew, packet-loss, partition, and signer-outage fault testing;
12. long-running fuzzing, SBOM/provenance, independent security audit, and verified private vulnerability reporting.

## Evidence rules

- Simulator-only results must be labelled simulator evidence.
- Loopback multi-process tests must be labelled local evidence.
- Microbenchmarks must not be converted into chain-level TPS claims.
- Every release claim must record repository URL, branch, commit SHA, clean/dirty state, toolchain, hardware, topology, workload, and raw artifact hashes.
- A feature is implemented only when the native node and validator path executes it deterministically and every validator reaches the same committed result.
- Unknown transaction, proof, or state-transition variants fail closed.
- Rewards must be funded by explicit balances, escrow, or governed pools; receipts must not silently mint value.

## Component posture

| Component | Current posture |
| --- | --- |
| Native node and validator protocol | Active development; local evidence only |
| PoCO task and settlement state machine | Active development; protocol hardening required |
| State, replay, and root commitments | Implemented development foundation |
| Finality types and independent verifier | Implemented development foundation |
| Parallel execution | Research and benchmarking; production proof incomplete |
| RPC, worker agent, CLI | MVP/development surfaces |
| Bridge, oracle, verifier sidecars | Experimental or launch-deferred unless explicitly promoted |
| Web4 frontend | Independent pre-release surface; not evidence of chain readiness |

## Go / no-go rule

Until every selected Day-1 blocker has an owner, executable gate, passing evidence packet, rollback procedure, and sign-off bound to one release commit, the correct decision remains **NO-GO**.
