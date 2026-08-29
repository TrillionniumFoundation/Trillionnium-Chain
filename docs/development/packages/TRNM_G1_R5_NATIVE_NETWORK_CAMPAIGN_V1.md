# G1-R5 native 4/7-node campaign package v1

Status: **MODULE_CLOSED_CANDIDATE for the campaign contract and preflight / execution blocked by accepted G1-R4**

Package ID: `G1_R5_NATIVE_NETWORK_CAMPAIGN_V1`  
Agent: `A07`  
Documentation base: `docs/agent-fleet-plan-v1-20260829@0c9368c3555faab0e497a5521321b2b2908d4d61`.

## Closed candidate surface

- exact 4-validator equal-weight and 7-validator unequal-weight fixtures;
- strict validator ID/key/proof-of-possession and weighted quorum checks;
- process/host/operator/custody placement with minimum three hosts;
- count-specific fault matrices:
  - 4-node: 3–1 progress and 2–2 safe stall/heal;
  - 7-node: 5–2 progress and weight-selected 4–3 safe stall/heal;
- normal finality, offline minority/rejoin, leader crash/TC, restart/catch-up, state sync, epoch/key rotation, signer fault and disk/I/O fault;
- active-validator weight checks against exact quorum;
- hard execution gate requiring accepted G1-R4;
- result contract that rejects transport-only smoke, unsigned/missing reports, conflicting finality, double-sign and application-root divergence;
- 12 retained manifest mutants.

## Why the 4/7 matrices differ

A node count is not a quorum argument. The 4-node fixture uses equal weights and quorum 3. The 7-node fixture uses weights `[4,3,3,2,2,1,1]`, total 16 and quorum 11. Its 4–3 stall partition deliberately selects four validators with weight 10, rather than assuming every four-validator side is below quorum.

## Execution boundary

The included fixtures are `candidate-harness-only`:

```text
g1_r4_exit=candidate
campaign_execution_authorized=false
results.present=false
validator_run_completed=false
transport_only=false
```

A future executor may run only after an accepted G1-R4 evidence ID is bound to the exact source/tree/binary/SBOM/genesis tuple. This package does not start a validator or reuse predecessor transport smoke as consensus evidence.

## Commands

```bash
bash scripts/ci/check_g1_r5_campaign_contract_v1.sh
```

The contract and 12 mutants were executed before publication in an isolated developer runtime. Exact-head clean-runner replay is still required.

## Result exit contract

A completed run requires one signed report per validator, immutable raw trace root, identical finalized height/block and application root, zero double-sign, `transport_only=false`, and exact scenario evidence. A missing or conflicting report invalidates the campaign.

## Remaining gaps

- accepted G1-R4 application/Safety/checkpoint/anti-rollback and fault evidence;
- exact rebuilt lab-validator binary and SBOM on that source;
- real multi-process/multi-host execution;
- external signer/watermark/state-sync integration;
- immutable signed reports and raw traces;
- independent campaign replay and reviewer signatures.

## Non-claims

```text
g1_r5_exit=false
campaign_execution_authorized=false
validator_run_completed=false
network_evidence_accepted=false
production_candidate=false
production_consensus_activation=false
```
