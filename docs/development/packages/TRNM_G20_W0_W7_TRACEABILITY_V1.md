# G2.0 W0-W7 traceability and code generation v1

Status: **MODULE_CLOSED_CANDIDATE for trace generation / G2.0 exit blocked**

Package ID: `G20_W0_W7_TRACEABILITY_V1`
Agent: `A10`
Upstream: A08 registry `c6749f9e959a0838b200190c730fc28e053bbec7`; A09 independent registry conformance `42584132125700b87c08ba7786f6ad4896afb7bf`.

## Objective

Generate one deterministic trace row for each operation kind `0..29` and make missing links visible as blockers rather than silently treating local kernels as integrated protocol authority.

## Link meanings

- W0: closed operation slot, schema/domain/bounds/error.
- W1: authorized `AgentTransactionV1` or explicitly typed system authority.
- W2: transaction batch/artifact DA and exact content root.
- W3: proposal/QC/finality binding.
- W4: deterministic execution receipt and application JMT root.
- W5: result/profile/challenge decision.
- W6: settlement intent/receipt and conservation.
- W7: RPC/WS/SDK/indexer/light-client projection.

## Invariants

1. Exactly 30 rows are generated from the A08 registry.
2. Required links are derived by closed plane policy, not by success claims.
3. Evidence starts `null`; a local SQLite root, fixture, composite root, or transport response cannot fill an authority link.
4. Kind 29 is disabled and contributes no admitted throughput.
5. `g2_0_complete` remains false until all applicable links for every enabled kind contain accepted evidence and two independent parser results.
6. Unknown planes fail generation.

## Commands

```bash
python3 tools/w0-w7-codegen/generate.py --output /tmp/w0-w7.json
bash scripts/ci/check_w0_w7_traceability_v1.sh
```

## Exit boundary

This package closes the generator and structural trace inventory only. The produced rows deliberately expose null schema hashes, access sets, owners and evidence until their owning packages deliver them. G2.0 promotion is `BLOCKED_UPSTREAM`.

## Non-claims

```text
g2_0_complete=false
wire_conformance_complete=false
rpc_sdk_complete=false
light_client_complete=false
node_support=false
production_candidate=false
```
