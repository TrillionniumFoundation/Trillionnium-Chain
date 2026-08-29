# G1-R3 ordinary Proposal execution target v1

Status: **candidate-only seam; G1-R3 exit remains open**

This package is subordinate to
[`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md)
and the canonical development plan. It records the first safe implementation
boundary after R2-B; it does not promote a validator or change any machine
truth flag.

## Implemented candidate boundary

The feature-gated `CandidateEffectDriverV1` now has an optional application
hook which may return the opaque Core-issued `ApplicationSealedValidV0` for
one exact ordinary `PayloadValidationRequest`. When the hook opts in, the
private driver performs this ordered sequence:

```text
ordinary Proposal
 -> Core validation request
 -> application-sealed proof
 -> Core delivery-only (D)
 -> exact SafetyState persist/readback
 -> same-owner SafetyRules rebind
 -> explicit AuthorityVote
 -> whole-node checkpoint CAS
 -> signer
 -> authenticated broadcast
```

The driver retains the original `SignedProposalV0` and checks its route,
block, and validation identity before accepting the proof. The proof and the
SafetyRules authority are non-cloneable Core-affined capabilities; callers
cannot provide a signing root, revision, receipt, or Vote carrier.

The ordinary hook also exposes an additive candidate-only outcome boundary:
the Core result states are `Sealed`, `Unavailable`, and
`DeterministicallyInvalid`, with `Unsupported` retained only as a capability
marker for an unimplemented adapter.
`Unavailable` and `DeterministicallyInvalid` are sent to Core as their exact
typed validation results and never enter the D/Vote or signer path. `Unsupported`
retains the legacy callback fallback for source compatibility only when that
callback leaves Core's SafetyState unchanged and returns no effects; a detected
SafetyState mutation or non-empty legacy effect list is rejected. The legacy
callback still has a mutable Core parameter, so volatile Core mutations outside
SafetyState remain an explicit candidate residual and do not close the ordinary
route. A hook that claims the linear request and silently returns `Unsupported`
is likewise not observable without a request-claim status accessor. `Unsupported`
is not an execution result.

The process fixture exposes this seam only through the explicit environment
variable `TRNM_POCO_EFFECT_PROCESS_ENABLE_ORDINARY_CANDIDATE=1`. Its default
remains fail-closed. The opt-in path derives fixture commitments and artifact
references, so it is useful for process ordering and fail-stop tests but is
not a production application/JMT execution result.

## Required follow-up before an R3 claim

- replace the fixture hook with the node-owned canonical body/evidence and
  runtime/JMT executor;
- bind parent state, validator set, parameters, and execution profile;
- map `Valid | Unavailable | DeterministicallyInvalid` without hidden writes;
- add process restart/SIGKILL, response-loss, root-mutation, and signer-custody
  evidence from an authorized clean clone;
- retain `production_candidate=false`, `production_consensus_activation=false`,
  and all live/atomic/finality flags until those conditions are independently
  reviewed.

The current candidate tests prove only the D-to-Vote ownership and ordering
seam. They do not close G1-R3, G1-R4 finality/apply/restart, G1-R5 network
evidence, or any production-readiness gate.
