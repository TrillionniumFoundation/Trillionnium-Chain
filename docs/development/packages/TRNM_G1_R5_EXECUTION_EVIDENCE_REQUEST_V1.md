# G1-R5 execution evidence request v1

Requester: `A07 / G1_R5_NATIVE_NETWORK_CAMPAIGN_V1`  
Branch: `agent/a07-g1-r5-native-network-campaign-v1-20260829`  
Current local result: campaign tooling `MODULE_CLOSED_CANDIDATE`; validator-run
execution `BLOCKED_UPSTREAM`.

## G1-R5-ICR-G1-R4-ACCEPTED-EVIDENCE-V1

Owners: A03, A04, A05, A06 and independent G1 reviewer/merge train.

A07 requires one accepted artifact—not a collection of local claims—binding:

```text
source commit and tree
binary SHA-256 and built provenance
SBOM SHA-256
genesis SHA-256
consensus parameters and validator-set hashes
application-finalization implementation/evidence digest
SafetyStore/tag-3 implementation/evidence digest
signer journal and external watermark digest
whole-node checkpoint CAS/readback digest
coherent namespace anti-rollback digest
multi-block/fork/GC evidence digest
fault/process/power-loss matrix digest
independent reviewer set and signatures
```

Required assertions:

```text
g1_r4_exit=true
application_finalization_accepted=true
safety_checkpoint_accepted=true
anti_rollback_accepted=true
fault_matrix_accepted=true
independent_review_accepted=true
production_or_activation_truth_changed=false
```

The evidence must be for one exact source/tree/binary/SBOM/genesis tuple.
Cross-PR claims with mismatched heads cannot be composed silently.

## A07 execution rule

Until the accepted artifact exists, both checked-in manifests retain:

```text
campaign_execution_authorized=false
outcome=BLOCKED_UPSTREAM
g1_r5_exit=false
validator_run_completed=false
network_evidence_accepted=false
```

Loopback transport, simulator output, same-host process farms and unsigned
reports are explicitly rejected as validator campaign evidence.

## Result acceptance after the gate opens

Every scenario must report exact start/end heights, validator/process/host
identities, partition/fault timeline, committed block/root sequence, timeout
certificates, restart/state-sync facts, signer/watermark/checkpoint heads and
raw artifact hashes. Acceptance additionally requires:

```text
transport_only_smoke=false
conflicting_finality=false
double_sign=false
root_divergence=false
at_least_two_independent_review_signatures=true
```

## Invalidation

Any change to source/tree, binary, SBOM, genesis, validator set, parameters,
application/Safety/checkpoint interfaces, fault hooks, topology, workload or
fault schedule invalidates authorization and all campaign results.
