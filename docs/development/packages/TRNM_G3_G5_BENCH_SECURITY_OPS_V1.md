# G3-G5 benchmark, security and operations preparation package v1

Status: **MODULE_CLOSED_CANDIDATE for validation contracts and runbooks / measurements, campaigns and activation blocked**

Package ID: `G3_G5_BENCH_SECURITY_OPS_V1`  
Agent: `A17`  
Upstream whole-node candidate: `a370a208b4a3f94d7fcafe73594dd84977551c0f`.

## Closed candidate surface

- strict benchmark/security/operations manifest validator;
- exact process/host/operator/region/custody topology accounting;
- workload byte roots and operation-mix accounting;
- ordered fault schedule bound to known topology identities;
- committed-goodput and finality definitions;
- raw-trace and no-orphan-metric requirements;
- exact comparator artifact and same-hardware/workload requirements;
- threat → invariant → mutant → owner → evidence rows;
- Critical/High activation blocking;
- dependency binding G0 through G2F;
- hard prohibition on premature superiority, public-testnet or production claims;
- 72-hour chaos, 7-day soak and 30-day soak campaign contracts;
- incident, disaster-recovery and key-rotation runbooks.

## Claim policy

`submitted_tps`, `ingress_tps` and unfinalized queue acceptance are never committed goodput. A metric is publishable only when it carries gate, workload, denominator and immutable raw-series root. A comparison additionally binds an exact comparator artifact, identical hardware/workload and fault model.

A “surpass” candidate requires:

1. every G0-G2F dependency accepted;
2. actual result traces;
3. at least two independent reproduction teams;
4. no blocking Critical/High finding;
5. `>=1.2x` on a declared workload with no weaker safety, availability, custody or proof boundary.

The included fixture is `harness-only`; it contains no measurements and allows no claim.

## Security gate

Open Critical or High findings keep all of these false:

```text
public_testnet_ready=false
production_candidate=false
production_activation=false
```

The severity vocabulary is exactly `Critical | High | Medium | Low`. “Accepted risk” is not “closed” for C0 or G5.

## Commands

```bash
bash scripts/ci/check_benchmark_security_ops_contract_v1.sh
```

The contract and 14 retained mutants were executed before publication in an isolated developer runtime. Exact-head clean-runner replay is still required.

## Remaining gaps

- accepted predecessor exits and exact release artifacts;
- real 4/7 then 7/31/100 process campaigns;
- multi-host/operator/region infrastructure and immutable raw traces;
- external consensus/crypto/DA/runtime/economic/custody reviews;
- operational RPC/WS/indexer/SDK and two-builder conformance;
- completed 72-hour, 7-day and 30-day campaigns;
- bug bounty and finding closure;
- economics/governance objects and activation signatures;
- `MIG-COMET-POCO` and `UP-V0-V1` ceremonies.

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
