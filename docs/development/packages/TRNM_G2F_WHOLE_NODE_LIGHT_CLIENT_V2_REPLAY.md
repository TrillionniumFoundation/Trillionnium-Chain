# G2F whole-node and light-client v2 replay

Status: **STOP_CONDITION for production authority; candidate model gaps closed where locally implementable**

Package: `G2F_WHOLE_NODE_LIGHT_CLIENT_V1`  
Agent: `A16`  
Exact base: PR #36, `feature/chain-a15-g2e-settlement-v2-20260830@fe61ee74b95b8768ba86f7a4a143a754d1b4159c`, tree `58dd1026fb58061848fb604e89c95ebdcb6a63b8`.

The package retains the complete PR #22 hardening candidate, the coordinated-view single-use permit and two independent light-client models. The GitHub Actions surface is restored to the frozen thirteen workflows; exact-head package execution is routed through the A00-owned payload-replay workflow rather than a package-specific workflow.

## Candidate closure

- six-plane atomicity and predecessor-bound whole-node checkpoint CAS;
- staged state sync and atomic namespace swap;
- copy, shallow-copy, rename, fork, residue and torn-state fences;
- two separately authored light-client verifiers;
- single-use owner permit binding namespace, predecessor, height, Order header, application root, manifest and six-plane identities;
- deterministic candidate view commitment `2fe37224cda2bd9c5bc28126aa257e1a74718b72086752447694ae89fd827dec`.

## Remaining stop conditions

- independent acceptance of retained P0 copy/fork/residue records;
- canonical Protocol09 application JMT and finalized Order authority;
- accepted A11–A15 interface digests;
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
