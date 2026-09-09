# CodeQL default setup v1

Status: repository-administration runbook. A settings write is not security acceptance, audit acceptance, production readiness, release authority, or activation authority.

## Purpose and trust boundary

`config/codeql-default-setup-v1.json` is the closed-world contract for GitHub CodeQL default setup. It requires GitHub Actions, JavaScript/TypeScript, Python, and Rust analysis, the extended query suite, local and remote threat sources, and standard GitHub-hosted execution. Rust is explicit and cannot be silently dropped.

The same contract pins two distinct GitHub-owned producers:

- aggregate `CodeQL`: GitHub Advanced Security app `id=57789`, slug `github-advanced-security`, owner `github`;
- per-language `Analyze (...)`: GitHub Actions app `id=15368`, slug `github-actions`, owner `github`, workflow path `dynamic/github-code-scanning/codeql`.

A check name alone has no authority. Exact-source evidence additionally requires the exact non-null head SHA, repository and head-repository identity, one shared Analyze check suite, one explicit validation workflow run, terminal success, and timestamps after the live configuration `updated_at`. The newest trusted aggregate result controls; an older success cannot hide a newer failure. Missing fields, duplicate paginated run IDs, cross-suite composition, cross-run composition, untrusted apps, stale checks and ambiguous duplicate Analyze checks fail closed.

`scripts/admin/apply_codeql_default_setup_v1.py` is dry-run only unless an administrator supplies all mutation acknowledgements. Evidence verification cannot be combined with mutation. A successful PATCH/readback report remains `VALIDATION_PENDING` until the returned validation run and exact-source checks are independently verified.

## Dry run and regression corpus

```bash
python3 scripts/admin/apply_codeql_default_setup_v1.py
python3 scripts/ci/test_codeql_default_setup_v1.py
```

Dry-run validates and prints the exact payload without reading credentials or calling GitHub. The regression corpus includes hostile producer spoofing, null/mismatched source identity, cross-suite and cross-run splicing, stale pre-configuration checks, missing live fields, branch movement before and after PATCH, pagination supersession and duplicate run IDs.

## Verify live configuration

The token needs repository Administration(read):

```bash
GH_TOKEN="${ADMIN_READ_TOKEN}" \
python3 scripts/admin/apply_codeql_default_setup_v1.py \
  --verify-live \
  --output /tmp/trnm-codeql-default-setup-live.json
```

The live response must explicitly contain `state`, `runner_type`, `runner_label`, `query_suite`, `threat_model`, `languages` and `updated_at`. The verifier does not synthesize `runner_type=standard` or any other missing setting.

## Apply under a protected change freeze

The token needs repository Administration(write). Establish a repository change freeze, record the current protected `main` SHA and a change-control ticket immediately before execution:

```bash
export GH_TOKEN="${ADMIN_WRITE_TOKEN}"
export TRNM_CODEQL_ADMIN_CHANGE_TICKET="issue-88/change-window-id"

python3 scripts/admin/apply_codeql_default_setup_v1.py \
  --apply \
  --acknowledge-admin-mutation \
  --acknowledge-change-freeze \
  --expected-current-main-sha "${OBSERVED_MAIN_SHA}" \
  --output /tmp/trnm-codeql-default-setup-applied.json
```

The command checks and records `main` at four barriers: before the live read, immediately before PATCH, immediately after PATCH and after live readback. Any movement invalidates the operation. GitHub does not expose a conditional default-setup PATCH, so the operational freeze is mandatory; the post-PATCH checks detect a race but cannot undo an already accepted settings mutation.

The PATCH response must provide a positive `run_id` and the exact in-repository Actions API `run_url`. Preserve both. The command returns `APPLIED_AND_LIVE_SHAPE_VERIFIED_VALIDATION_PENDING`; it deliberately does not claim CodeQL or security acceptance.

If GitHub rejects the explicit Rust language identifier, do not remove Rust from the contract. Repair the setting through the repository **Settings → Advanced Security → CodeQL analysis** administration surface or an API version that supports Rust, then rerun `--verify-live`.

## Exact-source acceptance

After the PATCH validation run completes, verify the unchanged source with the run ID captured above:

```bash
export TRNM_CODEQL_SETTINGS_VERIFICATION_TICKET="issue-88/read-window-id"
GH_TOKEN="${SECURITY_EVENTS_READ_TOKEN}" \
python3 scripts/admin/apply_codeql_default_setup_v1.py \
  --verify-live \
  --verify-evidence \
  --acknowledge-settings-verification-freeze \
  --evidence-sha "${EXACT_SOURCE_SHA}" \
  --validation-run-id "${PATCH_VALIDATION_RUN_ID}" \
  --output /tmp/trnm-codeql-exact-source-evidence.json
```

`--verify-evidence` requires `--verify-live` in the same invocation and cannot be combined with `--apply`. The four Analyze checks must belong to the supplied GitHub-generated dynamic CodeQL validation run and one check suite. The aggregate check must be produced by GitHub Advanced Security and begin only after every selected Analyze check has completed. Every check and suite must bind the exact repository and source SHA.

Evidence acceptance requires an independently enforced settings-change freeze and a non-empty verification ticket. The verifier snapshots the complete authority-bearing required-check inventory, performs the full configuration and exact-source check/suite/workflow verification twice, and rejects any configuration generation, inventory, or semantic result drift across the read window.

Retain the live configuration response, PATCH response, validation run, exact source/tree, complete paginated check-run inventory, suite identities, SARIF/alert inventory, change-control record and independent specialist disposition. Do not dismiss alerts, lower query coverage, remove Rust, self-approve, or treat a settings update as release authority.
