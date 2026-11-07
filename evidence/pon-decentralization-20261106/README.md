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
The [cited-profile crosscheck](cited-profile-crosscheck.json) also verifies that
the user's cited `9eda0ada15be1702269e08e527917568c710f4d3` profile and reviewed
base use the same exact Git blob and profile bytes.

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
`HOLD`. The final identity-reuse repair also retains known key/subject reuse
when ownership is unknown. Empty overlap lists reflect the absent deployment
roster; they do not prove absence of conflicts. The first frozen
[`8ae7093` report](development-assessment-8ae7093.json) is preserved unchanged.
The final-source validation separately recomputes the current file and compares
exact bytes.

[development-tests.json](development-tests.json) preserves the initial observed
uncommitted unit-test failures and their repair scope. They are development
observations, not failures of a deployed independent network. Final committed
source results and their complete command logs are recorded separately below.

## First frozen implementation validation

The [validation summary](validation/summary.json) retains completed commands
on local commit `8ae7093fc6380cef063b061ed8d7fe79749acc17`, tree
`a11d4b91519311c05b647e60a50b878b7ee9bafd`. Git Data publication produced
commit `79ed9de1a43462bb53de5dd66ba030bf7a764858` with that exact tree.
Commit metadata and ancestry differ; the original receipts retain the actual
local measured commit and are not relabeled as execution on a remote commit.
The raw [measured commit](validation/measured-source-commit.txt) and its
[local parent](validation/implementation-parent-commit.txt) retain their
Git commit preimages. No runtime activation or independent acceptance follows
from this byte equality.

| Executed scope on `8ae7093` | Observed result |
| --- | --- |
| Common-control and five-axis audit | 55 tests passed |
| Explicit WAN V3 control domains | 18 tests passed |
| Retained WAN V1/V2 behavior | 25 tests passed |
| Complete CI contract suite | 104 tests passed |
| Negative raw-source integrity suite | 43 tests passed |
| Project-boundary suite | 16 tests passed |
| Public evaluation lifecycle reference | 17 tests passed |
| Native-quorum independent reference oracle | 4 Python tests passed |
| Rust formatting | `cargo fmt --all -- --check` passed |
| Cargo workspace metadata | Locked/offline `--no-deps` metadata passed for 26 members; this does not execute the full transitive graph |
| Repository contract | Passed: 3,459 local links, 1,165 Rust files, 26 packages and 25 normal dependency edges |
| Actual source-only assessment | Reader output exactly matched the retained report; 23 missing-evidence findings, three unidentified key slots, threshold two |
| Raw source before/after | Both passed and exact reports matched: 10,677 entries and 1,026,717,644 bytes |

Each completed command has its full argv, source commit/tree, selected build
environment, before/after clean-source checks, exit code, raw-log byte length
and SHA-256 in `validation/`. The source-integrity suite's deliberate negative
controls print synthetic `FAIL` receipts; its actual unittest result is 43
passes and command exit 0. Those expected refusals are not a failed suite.
Counts are component controls, not an independent operational denominator.

### Preserved incomplete and failed observations

The strict full-workspace/all-target/all-feature Clippy command with
`-D warnings` did **not** complete successfully. The original four-worker
[attempt](validation/strict-clippy.json) returned 101 when the `syn` compiler
received SIGKILL. The single-worker [retry](validation/strict-clippy-j1.json)
also returned 101 when the `trnm-pon-node` Clippy compiler received SIGKILL.
Both raw logs are retained. The observed signals do not establish their root
cause; no lint pass or confirmed out-of-memory diagnosis is claimed.

The first native-quorum attempt has an empty log and no completion receipt;
its [incomplete observation](validation/native-quorum-incomplete.json) remains
unknown. After execution-environment recovery, the previously recorded Rust
toolchain path was absent. A bounded [retry](validation/native-quorum-bounded.json)
returned 127 before tests could execute. No native-quorum, native-release,
complete workspace unit-test or hosted-CI pass is inferred from these attempts.

Final read-only review then found a diagnostic omission: the core correctly
withheld independence credit when two unknown owners reused the same known
public key, but its controller-group overlap list omitted that known identity
relation. The follow-up adds explicit identity-reuse diagnostics without
inventing a controller or changing thresholds. The preceding test results
remain bound to `8ae7093`; any follow-up execution must have its own source
and command receipts.

## Final frozen implementation validation

The identity-reuse fix was frozen as local commit
`41e433a79548082f6eb4d9926f309153a16960d9`, tree
`1781f15299d9d221caa65491ee8a674bfa68fbff`. The
[final validation summary](validation-final/summary.json) retains 14 actual
completed command receipts on that clean source. Publication commit
`881768da89bae8d65277fc4da1963539c5e05e3c` has the exact same tree; the
[fetched-tree comparison](validation-final/source-publication-equivalence.json)
keeps commit metadata separate from source byte equality. The
[local commit preimage](validation-final/measured-source-commit.txt) preserves
the measured Git identity. This section and its final logs are added in an
evidence-only child, which does not change the tested implementation.

| Re-executed scope on `41e433a` | Observed result |
| --- | --- |
| Common-control/five-axis core, including six identity-reuse controls | 61 passed |
| WAN V3 control domains | 18 passed |
| WAN V1/V2 regression suite | 25 passed |
| Complete CI contract | 104 passed |
| Raw-source integrity counterexamples | 43 passed |
| Project boundary | 16 passed |
| Public evaluation lifecycle reference | 17 passed |
| Independent quorum reference oracle, implemented in Python | 4 passed |
| Source-only assessment reproduction | Exact current-report bytes matched; `HOLD`, 23 findings, three unidentified key slots, threshold two |
| Repository/Markdown contracts | Passed: 3,468 local links, 1,165 Rust files, 26 packages and 25 normal dependency edges |
| Raw tracked-source checks before/after | Passed with identical reports: 10,729 entries and 1,027,001,857 bytes |

All 14 final command receipts retain a clean initial source and unchanged final
source, exact command, exit code and original log digest. The identity-reuse
controls include unknown owners sharing a public key across roles/evaluation,
alternate routes for one role, a repeated subject without a fingerprint, and
unrelated unknown identities that must not be merged. The prior quorum,
denominator and acceptance calculations remain unchanged.

The [Rust source comparison](validation-final/rust-source-identity.json)
confirms that the complete `trillionnium` subtree and Rust toolchain inputs did
not change after `8ae7093`. Earlier formatting and metadata results retain that
execution identity. No new native execution or Clippy success is inferred;
both original SIGKILL failures, the incomplete native attempt and the unavailable
toolchain retry remain visible above. Full workspace unit tests, hosted CI and
all external qualification remain unclosed by these local checks.

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
