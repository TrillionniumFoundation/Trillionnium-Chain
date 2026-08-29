# G1-R5 native 4/7-node campaign contract v2

Status: **MODULE_CLOSED_CANDIDATE for A07-owned campaign tooling; BLOCKED_UPSTREAM for validator-run execution**

Package: `G1_R5_NATIVE_NETWORK_CAMPAIGN_V1`  
Owner: `A07`  
Branch: `agent/a07-g1-r5-native-network-campaign-v1-20260829`  
Bound A06 source: `feature/chain-g1-r4-fault-matrix-v2-20260829@e88cda9401eb6219fe1425bebb1ef6b54b4c429d`, tree `9c4249ce36061fcbd6eb8e522accd29127f7c01c`

## Candidate tooling closed

The v2 contract deterministically generates and validates both required
campaigns:

- 4-validator, equal-weight;
- 7-validator, unequal-weight.

Every validator has distinct validator, public-key, process, host, operator and
custody identities. At least three regions are required. Proof-of-possession is
domain-separated and checked. Voting power uses checked weighted quorum
`floor(2W/3)+1`.

The campaign identity binds exact:

```text
source commit and tree
binary SHA-256 and built state
SBOM SHA-256
genesis SHA-256
topology SHA-256
workload SHA-256
fault-schedule SHA-256
```

The workload is authenticated and bounded. The fault schedule includes normal
finality, minority outage/rejoin, leader crash/TC, partitions and healing,
restart/catch-up, trusted-checkpoint state sync, epoch/key rotation, signer
outage, disk/I/O failure and commit-response loss.

## Hard execution gate

A validator campaign cannot become executable unless the manifest contains:

```text
g1_r4_evidence.status=accepted
g1_r4_exit=true
independent_review_accepted=true
source commit/tree exactly equal campaign identity
non-zero evidence root
at least two independent reviewer IDs
binary_built=true
```

The checked-in fixtures intentionally carry none of those claims. Their exact
outcome is `BLOCKED_UPSTREAM`. The validator must not replace a real campaign
with loopback transport smoke, simulator output or same-host process counts.

## Result acceptance

A candidate result is accepted only when it is bound to the exact manifest and
contains the complete scenario set, two independent review signatures, and:

```text
transport_only_smoke=false
conflicting_finality=false
double_sign=false
root_divergence=false
```

No result fixture is checked in because the execution gate is not open.

## Replay

```bash
bash scripts/ci/check_g1_r5_campaign_contract_v2.sh
```

The gate regenerates both manifests, validates them, runs eight retained
mutants per topology, checks exact A06 source binding and preserves false
production/activation truth. The trusted runner workflow is
`.github/workflows/trnm-g1-r5-native-network-campaign-v2.yml`.

## Upstream blocker

Real campaign execution requires independently accepted G1-R4 application,
Safety, signer, checkpoint, coherent anti-rollback, multi-block and fault
matrix evidence on one exact source/tree/binary/SBOM/genesis tuple. Current A03,
A04, A05 and A06 PRs remain candidate or blocked and have not produced that
accepted Gate artifact.

## Explicit non-claims

```text
g1_r5_exit=false
campaign_execution_authorized=false
validator_run_completed=false
network_evidence_accepted=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```

A07 tooling is reviewable and locally closed; campaign execution is correctly
`BLOCKED_UPSTREAM`, not silently simulated.
