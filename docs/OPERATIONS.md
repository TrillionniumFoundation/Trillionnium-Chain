# OPERATIONS.md

Practical operator runbook for Trillionnium Chain (`chain/`) mainline.

## 0) Prerequisites
- Ignite CLI installed
- `jq` installed
- Local keyring has `alice` account

## 1) Start Local Chain
```bash
cd chain
ignite chain serve
```

In another terminal:
```bash
cd chain
chaind status | jq '.SyncInfo.latest_block_height'
```

## 2) Check Workload Params
```bash
chaind q workload params -o json
```

Expected default:
- `workloadDenom: "utrnm"`

## 3) Update Economic Denom (Authority Path)
> `update-params` requires module authority signer semantics.

```bash
AUTHORITY=$(chaind q auth module-account gov -o json | jq -r '.account.base_account.address')

chaind tx workload update-params \
  "$AUTHORITY" \
  '{"workloadDenom":"ufoo"}' \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

Re-check:
```bash
chaind q workload params -o json
```

## 4) Task Escrow + Burn Flow
### 4.1 Create Task (escrow to module)
```bash
chaind tx workload create-task \
  --bounty 100 \
  --ipfs-hash QmDemoTask \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 4.2 Complete Task (100% bounty burn)
```bash
chaind tx workload update-task \
  --id 0 \
  --status 2 \
  --result-hash QmDemoResult \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

## 5) Worker Lifecycle
### 5.1 Register Worker (stake lock)
```bash
chaind tx workload register-worker \
  --node-id node-1 \
  --ipfs-addr /ip4/127.0.0.1/tcp/4001 \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 5.2 Request Unbonding
```bash
chaind tx workload request-unbonding \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 5.3 Finalize Unbonding (after cooldown)
```bash
chaind tx workload finalize-unbonding \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

## 6) Governance Safety Hooks
### 6.1 Slash Worker (authority only)
```bash
chaind tx workload slash-worker \
  --worker <worker_addr> \
  --slash-percent 10 \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

### 6.2 Extend Unbonding (authority only)
```bash
chaind tx workload extend-unbonding \
  --worker <worker_addr> \
  --extra-blocks 50 \
  --from alice \
  --chain-id chain \
  --fees 200stake \
  --yes
```

## 7) Event Checks
Use tx query to inspect emitted events:
- `workload_create_task`
- `workload_update_task`
- `workload_register_worker`
- `workload_slash_worker`
- `workload_request_unbonding`
- `workload_finalize_unbonding`
- `workload_extend_unbonding`

Example:
```bash
chaind q tx <TX_HASH> -o json | jq '.events'
```

## 8) Fast Demo Script
One-command denom governance demo (with tx hash output + event verification):
```bash
cd chain
./tools/demo_denom_governance_flow.sh chain alice http://127.0.0.1:26657 ufoo
```
