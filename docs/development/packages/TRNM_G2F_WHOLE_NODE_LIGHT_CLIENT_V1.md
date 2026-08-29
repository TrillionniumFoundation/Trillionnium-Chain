# G2F whole-node authority, state sync and light-client package v1

Status: **MODULE_CLOSED_CANDIDATE for the independent authority model / production whole-node exit blocked**

Package ID: `G2F_WHOLE_NODE_LIGHT_CLIENT_V1`  
Agent: `A16`  
Upstream settlement candidate: `b009ac7f58fa3088136469598f9d2b6298a940d4`.

## Closed candidate surface

- exact five-plane snapshot over DA, Agent/Market, Execution, Verify/Challenge and Settlement;
- deterministic application-root projection committed by one Order proof;
- predecessor-bound whole-node checkpoint CAS;
- external monotonic anchor outside the modeled rollbackable namespace;
- exact response-loss replay;
- namespace, manifest, file-inventory and checkpoint checksum binding;
- coherent local rollback, copy/rename and torn-checkpoint rejection;
- staged state sync with chunk verification, root recomputation and atomic namespace swap;
- W3-W7 proof bundle covering Order, DA, execution, result, settlement and upgrade;
- a second standard-library verifier that imports neither the whole-node model nor TRNM implementation code;
- fail-closed negative corpus for missing planes/proofs, forks, root substitution, DAS while disabled, composite-root substitution, immature result, duplicate settlement and downgrade.

## Authority boundary

The model proves a candidate contract shape. Its application-root domain is explicitly a model domain and is **not** the production sparse JMT implementation. The Order proof uses bounded weighted/finality facts rather than production signature bytes. No signing, voting, broadcast, GC, settlement or activation capability is issued.

## Whole-node invariants

1. Every plane head names the same finalized Order height and block.
2. The exact five-plane set is required; extra, missing or duplicate planes fail.
3. Order `post_state_root` equals the deterministic root of the exact sampled bytes.
4. Checkpoint generation advances exactly once from the external anchor.
5. An exact already-committed target is replayable after response loss; a different target at the same predecessor is rejected.
6. Reopen requires exact chain, namespace, manifest, file inventory, local checkpoint and external anchor.
7. A coherent rollback of all local files still fails when the external anchor is ahead.
8. State sync never installs directly into the active namespace.
9. All chunks and the target Order/application root are verified before atomic swap.
10. Light-client proof families share one chain/height/block/application-root tuple.
11. `DA-DAS-V1`, candidate composite roots, immature results, duplicate settlement and downgrade are rejected.
12. Settlement proof explicitly states `poco_weight=false`.

## Commands

```bash
bash scripts/ci/check_whole_node_light_client_model_v1.sh
```

The script runs both independent implementations and retained mutants.

## Remaining gaps

- production JMT writer and membership proofs over canonical CEV1 bytes;
- cryptographic QC/TC/handoff verification in this new bundle;
- descriptor-bound/openat namespace ownership and real HSM/KMS/operator-quorum anchor;
- source-plane atomic snapshot or a production multi-store transaction protocol;
- normal node process ownership, signer, broadcast, restart and catch-up;
- real state-sync chunks, authenticated peers and disk/crash process matrix;
- two independently maintained production light clients;
- accepted G2.0 and G2A/B/D/C/E exit records.

## Non-claims

```text
g2f_exit=false
application_jmt_authority=false
production_anti_rollback_authority=false
state_sync_production=false
light_client_spec_complete=false
node_support=false
production_candidate=false
production_consensus_activation=false
```

## Downstream invalidation

Any change to a plane root, Order proof statement, checkpoint field, external-anchor rule, state-sync root, proof-family contract or no-downgrade rule invalidates this package and every G3-G5 result.
