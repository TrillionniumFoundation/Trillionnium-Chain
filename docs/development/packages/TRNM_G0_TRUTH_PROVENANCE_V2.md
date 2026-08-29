# G0 truth, provenance and handoff-contract refresh v2

Status: **MODULE_CLOSED_CANDIDATE for repository observation/validation; BLOCKED_UPSTREAM for G0 acceptance**

Package: `G0_TRUTH_PROVENANCE_V1`  
Owner: `A01`

## Closed repository-owned gaps

- refreshed the observed `main`, control, assessed-Plan and frozen-candidate identities;
- recorded the exact A12→A17 candidate publication heads and completed/success exact-head workflow runs;
- separated implementation/source commits from publication commits to avoid impossible self-referential hashes;
- evolved `agent-handoff-v1` additively for strict provenance SHA fields and compound evidence scopes;
- added a standard-library duplicate-key-rejecting handoff validator and retained negative mutants;
- retained all package acceptance, Gate, release and production authority as false.

## Handoff semantics

`head_commit` binds the semantic implementation/source commit described by the handoff. A containing publication commit cannot include its own hash. Publication commit/tree therefore belong in the source manifest, PR evidence, or the optional `publication_commit`/`publication_tree` fields of a later envelope. `implementation_commit`/`implementation_tree`, `base_sync_parent`, control/workflow bindings and specialized candidate evidence heads are optional but, when present, must be strict SHA-40 values.

Compound scope values such as `crate|model|fixture` are closed token sets, not free-form claims. A composite scope never promotes its authority; `candidate-non-normative` still requires `authority=candidate`.

## Exact command

```bash
bash scripts/ci/check_current_snapshot_v1.sh
```

## Remaining blockers

- independent A01 review and accepted evidence decision;
- branch protection, required status checks and signed release/tag provenance;
- G1 accepted evidence and real multi-host campaign;
- external anchor/HSM, physical-fault, audit, soak and governance evidence.

## Non-claims

```text
g0_exit=false
g1_exit=false
all_plan_gaps_closed=false
production_candidate=false
production_consensus_activation=false
release_ready=false
normative_freeze=false
node_support=false
```
