# TRNM Release Readiness

Updated: 2026-09-11  
Truth source: this file, assessed together with the exact Git commit.

## Current conclusion

**Not release-ready. Do not claim public-testnet or public-mainnet readiness.**

## Canonical implementation

The sole production-candidate direction is the self-developed native PoCO
stack:

`trnm-node -> trnm-mempool -> trnm-executor -> trnm-pouw/trnm-state -> finality receipts`

`trnm-protocol` and `trnm-runtime` remain reusable deterministic libraries.
Third-party consensus engines and application adapters are outside the current
tree and outside the repository boundary.

## Useful existing evidence

The repository contains native local-development evidence for:

- authenticated commands and validator votes;
- quorum and finality receipt verification;
- multi-node smoke, restart and round/view-change behavior;
- deterministic state roots, replay rejection and write-ahead recovery;
- bounded mempool admission, critical lanes and backpressure;
- conflict detection and grouped scheduling experiments;
- PoCO task, proof, challenge, timeout, resolution and settlement invariants;
- worker, RPC and release-evidence tooling.

Local evidence proves only the exact scenario and commit that produced it.

## Immediate repository follow-up

The dependency lock was removed together with the obsolete adapter dependency
graph. A newly generated lock must be reviewed and committed before this branch
can be considered merge-ready. Until then, locked Cargo commands are expected
to fail closed.

## P0 blockers

1. Authenticated multi-host topology, peer lifecycle and production state sync.
2. Secure consensus signing with remote signer or HSM/KMS and durable
   anti-equivocation protection.
3. Validator staking, unbonding, jail, slashing and evidence handling.
4. Threshold governance, timelock, emergency-role separation and parameter
   freeze.
5. End-to-end sustained throughput and finality latency under realistic
   multi-host workloads.
6. Disk-full, network-loss, clock-skew, key-loss and disaster-recovery drills.
7. Durable indexer, explorer, historical query and archive strategy.
8. Public anti-spam, fee, sponsor and state-retention economics.
9. Independent security audit, long-running fuzz evidence, SBOM and build
   provenance.
10. Verified private vulnerability-reporting route and assigned triage owner.

## Evidence rules

- Scheduler microbenchmarks are not chain TPS.
- Single-host or loopback tests are not multi-host readiness.
- A release statement must record branch, commit, clean-tree status, commands,
  configuration hashes and produced evidence hashes.
- Archived planning and historical reports do not override this file.
- Any capability outside the native path is non-canonical.

## Go/no-go

Until every P0 blocker has a reproducible, reviewed and commit-bound evidence
packet, the public release decision remains **NO-GO**.
