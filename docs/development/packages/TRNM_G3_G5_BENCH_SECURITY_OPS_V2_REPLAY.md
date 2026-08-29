# G3-G5 benchmark, security, operations and activation-gate v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A17-owned contracts; BLOCKED_UPSTREAM by A16 STOP_CONDITION and absent real campaigns/audits**

Package: `G3_G5_BENCH_SECURITY_OPS_V1`  
Agent: `A17`  
Exact base: PR #37, `feature/chain-a16-g2f-whole-node-light-client-v2-20260830@b1b10e1bd4e89ef64abd81f2e79f106535537532`, tree `ab3396de7f7e18aef80432f7764857d8e0820a1c`.

## Replayed contracts

The package replays the PR #19 benchmark manifest/schema, topology/workload/fault/metric requirements, threat register, incident/DR/key-rotation runbook and public-testnet campaign contract. It intentionally does not replay PR #19's modification to a shared payload workflow; A17 now owns a dedicated workflow.

## Strict claim and activation gate

The v2 gate denies claims unless all of the following are simultaneously true:

- exact accepted G0 through G5 evidence with two independent replays each;
- exact release, workload, trace and comparator roots;
- same hardware and workload for comparison;
- committed goodput plus Order/result/settlement p99 metrics;
- at least 100 processes, 7 hosts, 5 operators, 3 regions and 3 custody domains;
- at least 7-day soak for scoped comparison/public testnet and 30-day soak for production;
- zero open Critical/High findings;
- independent consensus/crypto audits, economic review and red team;
- SLO, incident, restore, key rotation, state-sync and observability drills;
- a narrow workload scope rather than a universal superiority claim.

Synthetic complete evidence exists solely to test deterministic decision logic. Real claim authorization remains false.

## Commands

```bash
bash scripts/ci/check_g3_g5_source_binding_v2.sh
bash scripts/ci/check_g3_g5_replay_v2.sh
```

## Non-claims

```text
g3_exit=false
g4_exit=false
g5_exit=false
benchmark_results_present=false
surpass_claim_allowed=false
public_testnet_ready=false
production_candidate=false
production_consensus_activation=false
```
