# Public-testnet campaign contract v1

Status: **preparation only; campaign not run**.

## Entry conditions

- accepted G0, G1, G1.5, G2.0 and G2A-G2F exits;
- exact signed source/binary/SBOM/genesis/parameter artifacts;
- no blocking Critical/High finding;
- independent clients and operator runbooks;
- replayable benchmark/topology/workload/fault manifests.

## Campaign ladder

1. 4/7-node safety and recovery baseline;
2. 7/31/100 process WAN profile with explicit host/operator/region counts;
3. 72-hour continuous chaos;
4. 7-day multi-region soak;
5. 30-day multi-region soak;
6. upgrade, key rotation, state-sync, backup/restore and disaster-recovery exercises;
7. independent operator onboarding and incident drills.

## Mandatory fault families

Process kill, host power loss, partition/heal, slow/refusing leader, equivocation, DDoS, signer/HSM outage, disk full, I/O uncertainty, WAL/snapshot/database rollback, state-sync restart, DA withholding/repair, challenge/settlement adversaries, epoch handoff and key rotation.

Every run retains raw successes, failures and mutants. A later pass never deletes a failed invariant.

## Reset semantics

A testnet reset creates a new chain/genesis/manifest ID. It cannot be counted as continuous uptime or history for the prior network.
