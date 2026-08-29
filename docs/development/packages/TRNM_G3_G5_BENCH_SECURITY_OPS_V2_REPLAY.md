# G3-G5 benchmark, security, operations and activation-gate v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A17-owned contracts; BLOCKED_UPSTREAM by A16 STOP_CONDITION and absent real campaigns/audits**

Package: `G3_G5_BENCH_SECURITY_OPS_V1`  
Agent: `A17`  
Exact base: PR #37, `feature/chain-a16-g2f-whole-node-light-client-v2-20260830@1a2efe08295cfa5ab745047bc75f37890d3ef58d`, tree `5396675fb3d3c991c561de16b07dbeff6afcc220`.

The package retains strict topology/workload/fault/metric contracts, threat mapping, runbooks and a fail-closed claim/activation gate. GitHub Actions uses the frozen thirteen-workflow tree `dc9157617e7d00750f878aad33ee9b5cae5d9d5d` and A00 exact-head control commit `d1bbbb43d385dbadadb34710610a49e43c498863`.

Synthetic evidence exists only to test deterministic decision logic. It does not authorize a real claim.

## Required before any claim

- accepted G0 through G5 evidence with two independent replays;
- real 4/7/31/100-process multi-host campaigns and signed raw traces;
- exact comparator artifact on the same hardware and workload;
- zero open Critical/High findings;
- independent consensus/crypto/economic audits and red team;
- incident, restore, key rotation, state-sync and observability drills;
- 72-hour, 7-day and 30-day soak evidence;
- governance and activation ceremony.

```text
g3_exit=false
g4_exit=false
g5_exit=false
benchmark_results_present=false
surpass_claim_allowed=false
public_testnet_ready=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```
