# G1-R4 finalization/apply/recovery target v1

Status: **candidate-only contract slice; G1-R4 exit remains open**

This package records the smallest follow-on slice after the candidate R3
ordinary Proposal seam.  It is subordinate to the canonical Chain
development plan and does not change any production or activation truth.

## Implemented candidate boundary

The lab-only finalization owner already performs the ordered Core/application
boundary:

```text
Core finalization queue front
 -> application intent marker
 -> native application commit
 -> fresh committed application readback
 -> Core application-finalization receipt
 -> tag-3 SafetyState persist/readback
 -> successor whole-node checkpoint CAS
 -> Ready/reopen
```

This tranche makes the process-loss marker boundary directly testable without
exporting the owner or its store handles.  The test matrix now proves:

- an exact marker survives until an explicit recovery owner reads it;
- an exact retry clears the marker only after proof-named application
  readback;
- a second retry with no marker is idempotent;
- a substituted source-artifact digest fails closed and leaves the marker
  available for an operator/recovery decision.

The marker helper and matrix are compiled only under
`lab-validator-runtime-test-support`.  They are not a production recovery
endpoint and do not make `Effect::Finalize` available in the generic effect
driver.

## G1-R4A child tranche

[`TRNM_G1_R4A_FINALIZATION_INTENT_PROCESS_MATRIX_V1.md`](TRNM_G1_R4A_FINALIZATION_INTENT_PROCESS_MATRIX_V1.md)
adds an exact source-derived publication-repair owner and five
independent-process SIGKILL cuts around the marker write/clear algorithm. The
production WAL remains byte-identical; the test-only build derives its process
copy from the reviewed WAL and fails closed if that preimage changes. This
tranche covers only the intent fence—not the application/Safety/checkpoint
chain.

## Required follow-up before an R4 claim

- inject and record SIGKILL, response-loss, disk-full and torn-write cuts at
  each application/Safety/checkpoint boundary;
- reopen through a separate process using authenticated Core proof, exact
  body/overlay lineage and a real runtime/JMT application owner;
- prove ascending multi-block finalization, queue/head CAS atomicity,
  anti-rollback and losing-fork retention/reclamation;
- repeat from an authorized clean clone and add independent process traces;
- only then evaluate the G1-R4 exit and downstream 4/7-node evidence.

The existing lab validator's long native-anchor test can spend substantial CPU
on repeated Ed25519 persistence validation.  A timeout or an interrupted run
is not a pass and is retained as an environment/baseline limitation rather
than hidden by this candidate package.

The following facts therefore remain false:

```text
finality_verified=false
native_application_finality_permit_integration=false
native_application_recovery_integration=false
process_kill_matrix_complete=false
production_candidate=false
production_consensus_activation=false
g1_r4_exit=false
```
