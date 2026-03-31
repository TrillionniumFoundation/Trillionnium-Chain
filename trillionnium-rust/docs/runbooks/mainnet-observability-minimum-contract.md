# TRNM Mainnet Observability Minimum Contract

This note freezes the **minimum operator-visible observability contract already present on `main`**.
It does **not** invent new metrics or claim full mainnet observability closure.
Its purpose is narrower:

- keep health probe aliases append-stable
- keep the `trnm-rpc` health body contract explicit
- preserve the existing `trnm-node` incident-summary metric bundle names
- preserve the current `trnm-worker-agent` submit log line shape used in operator handoff

Use this as a rehearsal/runbook reference until a fuller dashboard + alert pack lands.

## Scope boundary

This document only freezes surfaces already evidenced in code/tests under:

- `crates/trnm-rpc/src/health.rs`
- `crates/trnm-node/src/tests.rs`
- `crates/trnm-worker-agent/src/workflow.rs`

It should be read together with:

- `RELEASE_READINESS.md`
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`

## 1. `trnm-rpc` health probe aliases

The current `trnm-rpc` health server intentionally accepts the following case-insensitive aliases as health/readiness/liveness/status probes:

- `/health`, `/health/`, `/healthz`, `/healthz/`
- `/live`, `/live/`, `/livez`, `/livez/`
- `/ready`, `/ready/`, `/readyz`, `/readyz/`
- `/status`, `/status/`, `/statusz`, `/statusz/`
- `/-/health`, `/-/health/`, `/-/healthz`, `/-/healthz/`
- `/-/live`, `/-/live/`, `/-/livez`, `/-/livez/`
- `/-/ready`, `/-/ready/`, `/-/readyz`, `/-/readyz/`
- `/-/status`, `/-/status/`, `/-/statusz`, `/-/statusz/`

### Probe response contract

For any accepted probe alias, the current JSON body is:

```json
{
  "ok": true,
  "service": "trnm-rpc",
  "ts_unix_ms": 0,
  "version": 1
}
```

Operational meaning:

- `ok=true` means the HTTP probe surface itself is reachable.
- `service="trnm-rpc"` is the stable component discriminator.
- `ts_unix_ms` is the probe generation timestamp.
- `version=1` is the current health-body schema version.

This is a **surface-availability contract**, not a full dependency/read-model health proof.
Operators should not over-read it as indexer/read-model closure.

## 2. `trnm-node` incident-summary bundle names

`trnm-node` tests already keep the following incident-facing bundle append-stable and ordered for operator-visible summaries:

- `apply_error_total`
- `rollback_total`
- `apply_error_rollback_share_bps`
- `timeout_migrated_total`
- `recovery_error_rate`
- `bft_observed_heights`
- `bft_committed_heights`
- `bft_commit_observed_height_rate_ppm`
- `bft_skipped_height_total`
- `bft_skipped_observed_height_rate_ppm`
- `bft_double_vote_total`
- `bft_auth_reject_bad_sig_total`
- `bft_auth_reject_replay_total`
- `bft_auth_reject_stale_total`
- `bft_auth_reject_stale_nonce_total`

### Minimal interpretation hints

- `apply_error_total` / `rollback_total` / `apply_error_rollback_share_bps`
  - use together to understand whether failures are propagating into rollback-heavy behavior.
- `timeout_migrated_total`
  - use as the first timeout-pressure counter in incident summaries.
- `recovery_error_rate`
  - keep distinct from raw totals; it is intentionally a rate field, not a counter.
- `bft_observed_heights` / `bft_committed_heights`
  - use together before drawing conclusions from skipped-height rates.
- `bft_skipped_height_total` / `bft_skipped_observed_height_rate_ppm`
  - summarize commit gap pressure against observed height progress.
- `bft_double_vote_total` / `bft_auth_reject_*`
  - use as the minimum operator-visible BFT auth/safety cluster before escalation.
- `bft_auth_reject_stale_total` / `bft_auth_reject_stale_nonce_total`
  - keep both append-stable for grep compatibility; today the alias resolves to the same stale-nonce rejection counter and should not be reinterpreted as a distinct source.

### Operator-visible summary template

A safe starter summary line for incident handoff is:

- `apply_error_total=<n> rollback_total=<n> apply_error_rollback_share_bps=<n> timeout_migrated_total=<n> recovery_error_rate=<n> bft_observed_heights=<n> bft_committed_heights=<n> bft_commit_observed_height_rate_ppm=<n> bft_skipped_height_total=<n> bft_skipped_observed_height_rate_ppm=<n> bft_double_vote_total=<n> bft_auth_reject_bad_sig_total=<n> bft_auth_reject_replay_total=<n> bft_auth_reject_stale_total=<n> bft_auth_reject_stale_nonce_total=<n>`

Keep field names verbatim so pager notes and release evidence remain grep-stable.

## 3. `trnm-worker-agent` submit log line

When `trnm-worker-agent` runs in submit mode, the current operator-visible stderr line is:

- `submitted=true submit_log=<path>`

Operational meaning:

- `submitted=true` tells the operator the submit branch actually executed.
- `submit_log=<path>` points to the persisted submit log file that should be attached during handoff/triage.

This line is intentionally small and path-oriented.
If richer structured logging lands later, prefer adding fields rather than renaming these two tokens.

## 4. Conservative rules for future changes

Until the unified dashboard/alert pack exists, apply these rules:

1. Prefer **adding** aliases/fields/metrics over renaming existing ones.
2. Treat the `trnm-rpc` health JSON body as append-stable.
3. Treat the `trnm-node` incident bundle names above as append-stable.
4. Treat `submitted=true submit_log=<path>` as the worker-agent minimum handoff line.
5. If a new surface claims to supersede one of the above, keep a compatibility path or update this runbook in the same patch.

## 5. What this document does not claim

This document does **not** claim that TRNM already has:

- a complete node/rpc/worker/oracle/bridge unified metrics contract
- dashboards
- alert thresholds
- incident severity conventions
- replay attribution fully wired into observability

Those remain open P0 observability closure items per the blocker board and gap matrix.
