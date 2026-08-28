# G1-R2B next implementation target v1

Status: **candidate-only target; no source-bound R2-B implementation or
promotion evidence**

The executable contract and negative truth gate are maintained in
[`TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md`](TRNM_G1_R2B_REAL_CORE_ADAPTER_EXECUTION_PACKAGE_V1.md),
[`trnm-g1-r2b-manifest-v1.toml`](trnm-g1-r2b-manifest-v1.toml), and
[`../../../scripts/ci/check_replay_to_core_r2b_contract_v1.sh`](../../../scripts/ci/check_replay_to_core_r2b_contract_v1.sh).

The g1-r2b worktree contains a candidate `CandidateCoreIngressV1` probe. It is
explicitly unbound and candidate-only; its synthetic proposal
material, local journal and library-level Core call do not authorize a live
adapter, a Core-generated receipt, process integration, or any production
claim. Until a clean source/tree tuple and process evidence are accepted,
`production_candidate=false`, `production_consensus_activation=false`, and
all R2-B authority flags remain false.

The required negative flags are frozen explicitly:

```text
live_core_adapter=false
core_ack_generated_by_core=false
core_ack_atomic_with_core=false
node_process_integration=false
```

The next code change after R2-A verification is a concrete sealed authority
inside the existing G1 process/Core boundary.

It must consume the coordinator's exact `CoreReplayRequestV1`, invoke the real
private Core ingress, and construct `CoreDurableReplayReceiptV1` only after:

```text
Core input accepted
 -> SafetyState/Core revision persisted
 -> durable state reopened/read back
 -> whole-node predecessor checkpoint unchanged
 -> acknowledgement digest derived from the durable result
```

Required fault cuts:

```text
before Core input
Core accepted / before persistence
persistence / before readback
readback / before replay ack
replay ack / before completion
completion / before response
```

Any uncertain Core outcome retains the pending record and returns no receipt.
No caller, CLI, generic callback or test carrier may construct the receipt in
production code.
