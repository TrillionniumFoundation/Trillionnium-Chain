# Main branch protection v1

Status: repository administration runbook; changing settings is not protocol, security, production, release, or activation acceptance.

## Purpose

`config/main-branch-protection-v1.json` is the closed-world contract for the canonical `main` branch. `scripts/admin/apply_main_protection_v1.py` generates the GitHub branch-protection payload, verifies that every required context completed successfully on one exact evidence commit, applies the payload only after two explicit administrative acknowledgements, and then reads the live settings back for an exact comparison.

The contract requires:

- two approvals;
- CODEOWNER review;
- stale-review dismissal;
- approval of the most recent push;
- resolved conversations;
- an up-to-date linear integration history;
- admin enforcement;
- denial of force pushes and branch deletion;
- repository truth, protocol, fuzz, Rust, external-evidence negative-contract, and CodeQL checks.

A skipped, neutral, queued, stale, missing, cancelled, timed-out, or failed required check is not success.

## Dry run

The default mode validates the closed-world configuration and prints the exact payload without reading credentials or mutating GitHub:

```bash
python3 scripts/admin/apply_main_protection_v1.py
python3 scripts/ci/test_main_protection_v1.py
```

## Evidence verification

Use a full exact-source commit whose required contexts are attached to that same SHA:

```bash
GH_TOKEN="${READ_TOKEN}" \
python3 scripts/admin/apply_main_protection_v1.py \
  --verify-evidence \
  --evidence-sha "${EXACT_ACCEPTED_SHA}" \
  --output /tmp/main-protection-evidence.json
```

The token is never written to the report. Verification does not apply settings.

## Apply

The administrator must first record the live `main` SHA and a change-control ticket. A race on `main`, missing successful evidence, missing acknowledgement, missing ticket, an inaccessible administration endpoint, or a mismatching readback aborts the operation.

```bash
export GH_TOKEN="${ADMINISTRATION_WRITE_TOKEN}"
export TRNM_ADMIN_CHANGE_TICKET="issue-40/change-window-id"

python3 scripts/admin/apply_main_protection_v1.py \
  --apply \
  --acknowledge-admin-mutation \
  --evidence-sha "${EXACT_ACCEPTED_SHA}" \
  --expected-current-main-sha "${OBSERVED_MAIN_SHA}" \
  --output /tmp/main-protection-applied.json
```

Retain the report, the exact configuration blob, the executing script blob, the API actor identity, the change-control record, and normal-actor negative traces for:

- direct push without a pull request;
- one approval only;
- stale approval after a new push;
- missing CODEOWNER approval;
- unresolved conversation;
- out-of-date branch;
- failed, skipped, neutral, or absent required context;
- admin direct push;
- force push;
- deletion.

## Non-claims

A successful settings write does not close independent review, CodeQL disposition, HSM/remote signer, host attestation, physical power-loss, multi-host, audit, soak, migration ceremony, governance, production, public-testnet, release, or activation gates. Those require their own exact-source evidence and authorized acceptance.
