# G2F whole-node and light-client v2 replay

Status: **STOP_CONDITION for production authority; candidate model gaps closed where locally implementable**

Package: `G2F_WHOLE_NODE_LIGHT_CLIENT_V1`  
Agent: `A16`  
Exact base: PR #36, `feature/chain-a15-g2e-settlement-v2-20260830@1ec2a1245e3241fd6925a5d5fa400f04374c8b4f`, tree `d314feacba8f1690b828eb63e67b019c7dbf5ed9`.

The package retains the complete PR #22 hardening candidate, the coordinated-view single-use permit and two independent light-client models. The GitHub Actions surface is the frozen thirteen-workflow tree `dc9157617e7d00750f878aad33ee9b5cae5d9d5d`; exact-head package execution is routed through A00 control commit `d1bbbb43d385dbadadb34710610a49e43c498863`.

The package-owned replay script runs Python conformance, two-client checks, state-sync/view-commitment checks, feature-gated Rust tests, strict Clippy and rustfmt. No Cargo command is embedded in the shared control workflow.

## Remaining stop conditions

- independent acceptance of retained P0 copy/fork/residue records;
- canonical Protocol09 application JMT and finalized Order authority;
- accepted A11-A15 interface digests;
- external monotonic anchor and HSM/KMS custody;
- normal node-process ownership plus real power-loss and multi-host evidence.

```text
g2f_exit=false
canonical_application_jmt=false
production_external_anchor=false
production_hsm_authority=false
node_support=false
production_candidate=false
production_consensus_activation=false
```
