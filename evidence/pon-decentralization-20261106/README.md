# Decentralization audit and declared-control evidence — 2026-11-06

This package continues the existing #688 integration candidate for audit §4.4.
It separates work access, data distribution, evaluation, release/upgrade
authority and funding/hardware concentration. The executable contract is
[DECENTRALIZATION_AUDIT_V1](../../docs/protocol/pon-nakamoto-v1/details/DECENTRALIZATION_AUDIT_V1.md).

## Source review

[source-inventory.json](source-inventory.json) records the exact reviewed base
commit, file hashes and observed source boundaries. It is a read-only source
inventory. It does not claim a deployed operator roster, physical custody,
external signature authentication, a measured concentration percentage or an
independent network experiment.

[source-bindings.json](source-bindings.json) retains the preimage for the
current audit's `chain_source_sha256`: hash the exact descriptor file bytes.
The descriptor binds the repository, base commit/tree and exact selected-source
inventory. This is a source identity reference, not a complete runtime-material
SHA-256 seal or a native binary digest. `profile_sha256` hashes the exact base
`config/pon/devnet-v1.json` bytes. Unobserved Hepta source, binaries and deployed
network/genesis/parameter identities must remain absent; zero or invented hashes
cannot replace them.

The base development configuration remains three evaluator signing identities
with a threshold of two under an explicit attested development profile. The separately
selected native quorum V2 profile uses controlled development keys. Release
signatures count pinned keys; data discovery yields location hints; local
retention performs actual byte readback. None of those observations identifies
independent administrators.

## Actual current input and derived result

[current-input.json](current-input.json) supplies the actual development profile's
three configured signer slots and threshold of two, with an empty deployed key
and controller inventory. No guessed fingerprints, operator names, accounts,
funding balances or hardware capacities are inserted. The separate four-key
native-quorum source facts remain in `source-inventory.json`; they are not
silently substituted for this selected development profile.

The input's one-second reference window is a source-only assessment scope.
It contains no operator observations and is not a physical experiment, uptime
interval or PN5 campaign. All four actual production-access facets remain
unknown. Funding/hardware units and denominators remain unknown; missing
deployment-context fields are omitted explicitly.

The reader actually processed this input with:

```sh
python3 scripts/pon_decentralization_audit.py \
  --input evidence/pon-decentralization-20261106/current-input.json \
  --output evidence/pon-decentralization-20261106/current-assessment.json
```

The command returned exit 0 and wrote the report, subsequently retained unchanged
as [development-assessment-v1.json](development-assessment-v1.json), with `status: HOLD` and
23 accounting findings. These findings are missing-evidence/accounting
conditions, not 23 independently confirmed vulnerabilities. The report retains:

- Three configured key slots without identified deployed custody records in
  this input; approving and blocking control-group minima are `null`.
- Missing deployed `root`, `release`, `upgrade`, `recovery` and `witness` route
  inventories. This is missing deployment evidence, not absence of the source
  implementations.
- Six missing context fields: Chain binary, Hepta source and binary, network,
  genesis and parameters.
- Unknown funding and productive-hardware denominators; no concentration
  percentage is invented.
- False external-reference authentication, independent administration,
  permissionless utility, public readiness and production activation.

During concurrent implementation, the core added explicit cross-role and
evaluation/authority overlap diagnostics. A subsequent comparison against that
new output shape did not match this first retained report. The
[initial QA record](documentation-qa-initial.json) preserves the mismatch and the
observed added fields. This first report is historical source-only output;
the final implementation needs its own newly executed report. The CLI now uses
create-only output files so a previous report cannot be silently relabeled.

## Current implementation assessment

[current-assessment.json](current-assessment.json) is the newly executed output
of the completed reader on the same retained source-only input. It adds explicit
cross-role and evaluation/authority overlap fields while retaining the 23
missing-evidence findings, unknown ownership and resource denominators, and
`HOLD`. Empty overlap lists reflect the absent deployment roster; they do not
prove absence of conflicts. The final-source validation separately recomputes
this file and compares exact bytes.

[development-tests.json](development-tests.json) preserves the initial observed
uncommitted unit-test failures and their repair scope. They are development
observations, not failures of a deployed independent network. Final committed
source results and their complete command logs are recorded separately below.

## Execution status

The source inventory records only inspected baseline bytes. Implementation
execution and validation results must be recorded separately against the exact
changed source, commands and raw outputs after those commands actually finish.
This package does not transfer historical tests to new code or count a planned
test as executed. The final validation record must retain any initial failures,
fixes and unexecuted gates.

## External gates

The package has not acquired independently administered evaluator, provider,
root-signing or recovery-witness deployments. It has not measured complete
network funding or productive-hardware shares. It has not run the frozen PN5
campaign for at least 72 real hours on at least three independent administrators
and failure domains. These gaps cannot be closed with local JSON fixtures or
extra processes/keys controlled by the same operator.

`independent_accepted`, `permissionless_utility_accepted`, `pn5_accepted`,
`public_network_ready` and `production_activation` remain false. Current and
historical public-service, work-security, whole-chain PQ, model-benefit and
external-effect results retain their original identities and meanings.
