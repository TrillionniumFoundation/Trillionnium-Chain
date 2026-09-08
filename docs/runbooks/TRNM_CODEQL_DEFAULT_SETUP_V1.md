# CodeQL default setup v1

Status: repository-administration runbook. A settings write is not security acceptance, audit acceptance, production readiness, release authority, or activation authority.

## Purpose

`config/codeql-default-setup-v1.json` is the closed-world contract for GitHub CodeQL default setup. It requires GitHub Actions, JavaScript/TypeScript, Python, and Rust analysis, the extended query suite, local and remote threat sources, and standard GitHub-hosted execution. Rust is explicit and cannot be silently dropped.

`scripts/admin/apply_codeql_default_setup_v1.py` is dry-run only unless an administrator supplies all mutation acknowledgements. It reads the current `main` SHA before changing settings, applies the exact configuration, and verifies the live settings after GitHub accepts the update.

The aggregate `CodeQL` check and every required `Analyze (...)` check must later complete with `success` on one exact source SHA. `neutral`, skipped, absent, queued, cancelled, timed out, stale, or failed checks are not acceptance. An empty alert query is not proof of zero findings when a language configuration is missing.

## Dry run and regression corpus

```bash
python3 scripts/admin/apply_codeql_default_setup_v1.py
python3 scripts/ci/test_codeql_default_setup_v1.py
```

Dry-run validates and prints the exact payload without reading credentials or calling GitHub.

## Verify live configuration

The token needs repository Administration(read):

```bash
GH_TOKEN="${ADMIN_READ_TOKEN}" \
python3 scripts/admin/apply_codeql_default_setup_v1.py \
  --verify-live \
  --output /tmp/trnm-codeql-default-setup-live.json
```

## Apply

The token needs repository Administration(write). Record the current protected `main` SHA and a change-control ticket immediately before execution:

```bash
export GH_TOKEN="${ADMIN_WRITE_TOKEN}"
export TRNM_CODEQL_ADMIN_CHANGE_TICKET="issue-88/change-window-id"

python3 scripts/admin/apply_codeql_default_setup_v1.py \
  --apply \
  --acknowledge-admin-mutation \
  --expected-current-main-sha "${OBSERVED_MAIN_SHA}" \
  --output /tmp/trnm-codeql-default-setup-applied.json
```

If GitHub rejects the explicit Rust language identifier, do not remove Rust from the contract. Repair the setting through the repository **Settings → Advanced Security → CodeQL analysis** administration surface or an API version that supports Rust, then rerun `--verify-live`. GitHub default setup supports Rust, and this repository already treats `/language:rust` as a required base configuration.

## Exact-source acceptance

After GitHub completes its validation run, retrigger or synchronize the target pull request and verify the unchanged exact source:

```bash
GH_TOKEN="${SECURITY_EVENTS_READ_TOKEN}" \
python3 scripts/admin/apply_codeql_default_setup_v1.py \
  --verify-live \
  --verify-evidence \
  --evidence-sha "${EXACT_SOURCE_SHA}" \
  --output /tmp/trnm-codeql-exact-source-evidence.json
```

Retain the live configuration response, validation run, exact source/tree, complete check-run inventory, SARIF/alert inventory, change-control record, and independent specialist disposition. Do not dismiss alerts, lower query coverage, remove Rust, or treat a settings update as release authority.
