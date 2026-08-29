# G2F whole-node, state-sync and light-client v2 replay

Status: **STOP_CONDITION with one coordinated-view P0 closed-candidate; BLOCKED_UPSTREAM for canonical/production authority**

Package: `G2F_WHOLE_NODE_LIGHT_CLIENT_V1`  
Agent: `A16`  
Exact base: PR #36, `feature/chain-a15-g2e-settlement-v2-20260830@048a5358c38dfcb8e150c0447c1b3d99c355942b`, tree `ef02fcb1112c52aaf40e03fe51a1447bf691b5df`.

## Replayed candidate hardening

This branch imports the complete 22-path PR #22 candidate: six-plane atomicity model, sparse JMT-shaped proof model, two independent light clients, staged state-sync, copy/rename/fork/residue/rollback fences and feature-gated descriptor/openat namespace identity plus external-anchor shapes.

## Coordinated view closure

`G2F-M-SYNC-COORDINATED-NONZERO-VIEW` is closed at candidate-model scope by a separately administered single-use owner permit over the immutable ManifestView commitment. The commitment includes:

- namespace identity and predecessor checkpoint;
- height, Order header, application root and manifest hash;
- sorted six-plane names, generations, source identities and state roots;
- nonce and view-format version.

Changing any field while merely recomputing the stage digest fails before permit consumption. Permit replay, wrong issuer, expiry and token mutation also fail closed.

The HMAC issuer is an assurance model, not a production HSM or finality authority. The package remains `STOP_CONDITION` because the other retained P0 copy/fork/residue records still need independent acceptance and canonical JMT, real external anchor, accepted upstream interfaces and process/power-loss evidence remain absent.

## Commands

```bash
bash scripts/ci/check_g2f_source_binding_v2.sh
bash scripts/ci/check_g2f_replay_v2.sh
```

## Non-claims

```text
g2f_exit=false
canonical_application_jmt=false
accepted_upstream_interfaces=false
production_external_anchor=false
production_hsm_authority=false
state_sync_production=false
node_support=false
production_candidate=false
production_consensus_activation=false
```
