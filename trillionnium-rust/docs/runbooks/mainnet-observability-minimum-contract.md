# TRNM Mainnet Observability Minimum Contract

This note freezes the **minimum operator-visible observability contract already present on `main`**.
It does **not** invent new metrics or claim full mainnet observability closure.
Its purpose is narrower:

- keep health probe aliases append-stable
- keep the `trnm-rpc` health body contract explicit
- preserve the existing `trnm-node` incident-summary metric bundle names
- preserve the current `trnm-worker-agent` operator-visible handoff and batch-summary line shapes used in operator handoff

Use this as a rehearsal/runbook reference until a fuller dashboard + alert pack lands.

## Scope boundary

This document only freezes surfaces already evidenced in code/tests under:

- `crates/trnm-rpc/src/runtime/http.rs` (runtime path) and `crates/trnm-rpc/src/health.rs` (mirrored compatibility path)
- `crates/trnm-node/src/runtime/metrics_aggregation/summary_format.rs`
- `crates/trnm-worker-agent/src/workflow_ops.rs`
- `crates/trnm-worker-agent/src/assigned.rs`

It should be read together with:

- `RELEASE_READINESS.md`
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`

## 1. `trnm-rpc` health probe aliases

The current `trnm-rpc` health server intentionally accepts the following case-insensitive aliases as health/readiness/liveness/status probes.
The runtime implementation in `src/runtime/http.rs` is the primary truth source; the mirrored `src/health.rs` path should stay behaviorally aligned until the compatibility copy is retired:

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

Query strings are ignored for alias matching. For example, `GET /healthz?probe=lb HTTP/1.1`, `HEAD /-/readyz?probe=lb&from=ops HTTP/1.1`, and `/-/statusz/?from=ops` still bind to the same health contract as their path-only forms.

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

### HTTP method semantics

For accepted probe aliases, the transport semantics are also part of the minimum contract:

- `GET` returns the JSON body above.
- `HEAD` returns the same status code and `Content-Length` that the equivalent `GET` body would have produced, but with no response body bytes.
  This stays true even when operators probe an accepted alias with a query string (for example `HEAD /-/readyz?probe=lb&from=ops HTTP/1.1`).

This matters for load balancers and lightweight operator probes that rely on header-only checks.
If the body later grows by additive fields, `HEAD` should continue to mirror the equivalent `GET` payload length rather than inventing a separate schema.

This is a **surface-availability contract**, not a full dependency/read-model health proof.
Operators should not over-read it as indexer/read-model closure.

### Negative-path transport semantics

The minimum operator-facing contract also includes the current fail-closed transport split around this probe surface:

- a **recognized** probe alias returns `200 OK` with the schema above for `GET`, or the equivalent header-only response for `HEAD`
- an **unknown but otherwise valid** HTTP request path returns `404 Not Found` with the current JSON error envelope `{"ok":false,"code":"NOT_FOUND"}` for `GET`, or the equivalent header-only response for `HEAD`
- a **malformed** HTTP request line returns `400 Bad Request` with the current JSON error envelope `{"ok":false,"code":"BAD_REQUEST","message":"invalid http request"}`

Operational meaning:

- `404` means the probe surface was reached but the requested path is outside the current contract
- `400` means the request itself was malformed and should be treated as probe/client error rather than as a service-specific readiness signal
- for a syntactically valid but unknown path probed with `HEAD`, the server keeps the same status code and `Content-Length` that the equivalent `GET` envelope would have produced, rather than inventing a probe-specific error shape
- for a malformed request line that cannot be parsed into a trustworthy method/path pair, the current implementation fails closed with a JSON `400` body instead of attempting to preserve `HEAD`-style header-only semantics

This distinction matters during load balancer, sidecar, and operator triage because it separates "wrong endpoint" from "broken request generation" without overloading the health/readiness meaning of `200`, while also documenting the current fail-closed behavior for malformed requests.

## 2. `trnm-node` incident-summary bundle names

`trnm-node` summary-format tests already keep the following incident-facing bundle append-stable and ordered for operator-visible summaries:

- `critical_wait_density_ppm`
- `critical_wait_peak_density_ppm`
- `critical_wait_active_heights`
- `critical_wait_active_height_rate_ppm`
- `critical_wait_active_observed_height_rate_ppm`
- `critical_wait_density_avg`
- `critical_wait_density_avg_milli`
- `critical_wait_active_height_share_ppm`
- `rollback_block_total`
- `rollback_active_heights`
- `rollback_block_rate`
- `rollback_block_rate_ppm`
- `rollback_active_height_rate_ppm`
- `rollback_active_observed_height_rate_ppm`
- `rollback_density_avg`
- `rollback_density_avg_milli`
- `rollback_active_height_share_ppm`
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
- `bft_round_change_total`
- `bft_round_change_per_height_ppm`
- `bft_round_change_active_heights`
- `bft_round_change_active_height_rate_ppm`
- `bft_round_change_active_observed_height_rate_ppm`
- `bft_round_change_density_avg`
- `bft_round_change_density_avg_milli`
- `bft_round_change_active_height_share_ppm`
- `bft_round_change_backoff_total_ms`
- `bft_round_change_backoff_avg_ms`
- `bft_round_change_backoff_active_heights`
- `bft_round_change_backoff_active_height_rate_ppm`
- `bft_round_change_backoff_active_observed_height_rate_ppm`
- `bft_round_change_backoff_density_avg_ms`
- `bft_round_change_backoff_density_avg_milli`
- `bft_round_change_backoff_active_height_share_ppm`
- `bft_round_change_backoff_max_ms`
- `bft_round_change_backoff_wall_share_ppm`
- `bft_round_change_backoff_share_ppm`
  - canonical vs compatibility: treat `bft_round_change_backoff_wall_share_ppm` as the descriptive wall-clock share name and `bft_round_change_backoff_share_ppm` as the grep-stable compatibility alias; today they intentionally carry the same value.
- `bft_double_vote_total`
- `bft_auth_reject_bad_sig_total`
- `bft_auth_reject_replay_total`
- `bft_auth_reject_stale_total`
- `bft_auth_reject_stale_nonce_total`
  - canonical vs compatibility: treat `bft_auth_reject_stale_nonce_total` as the descriptive stale-nonce counter and `bft_auth_reject_stale_total` as the grep-stable compatibility alias until the broader metrics contract is explicitly split.
- `bft_leader_missed_total`
- `bft_leader_missed_max`
- `bft_leader_missed_top_share_ppm`
- `bft_leader_missed_active_validators`
- `bft_leader_missed_active_validator_share_ppm`
- `bft_leader_missed_active_heights`
- `bft_leader_missed_active_height_rate_ppm`
- `bft_leader_missed_active_observed_height_rate_ppm`
- `bft_leader_missed_density_avg`
- `bft_leader_missed_density_avg_milli`
- `bft_leader_missed_active_height_share_ppm`
- `bft_leader_missed_proposals`

### Minimal interpretation hints

- `critical_wait_density_ppm` / `critical_wait_peak_density_ppm` / `critical_wait_active_heights`
  - use together as the first operator-visible contention/queue-pressure cluster before escalating into scheduler or proposer triage.
- `critical_wait_active_height_rate_ppm` / `critical_wait_active_observed_height_rate_ppm`
  - preserve both because active-height share and observed-height share answer different questions during incident review; the observed-height variant should stay lower-bounded by total progress rather than by only active heights.
- `critical_wait_density_avg` / `critical_wait_density_avg_milli` / `critical_wait_active_height_share_ppm`
  - keep as the normalized density/share trio for dashboards and handoff notes.
- `rollback_block_total` / `rollback_active_heights` / `rollback_block_rate` / `rollback_block_rate_ppm`
  - use together to separate absolute rollback volume from height-level blast radius.
- `rollback_active_height_rate_ppm` / `rollback_active_observed_height_rate_ppm`
  - preserve both because rollback pressure against active heights and observed heights should remain grep-stable and comparable across summaries.
- `rollback_density_avg` / `rollback_density_avg_milli` / `rollback_active_height_share_ppm`
  - keep as the normalized rollback intensity/share trio for operator notes.
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
- `bft_round_change_total` / `bft_round_change_per_height_ppm` / `bft_round_change_active_heights`
  - use as the minimum round-change pressure cluster before escalating to proposer rotation, quorum-health, or peer-lag review.
- `bft_round_change_active_height_rate_ppm` / `bft_round_change_active_observed_height_rate_ppm`
  - preserve both because round-change pressure against active heights and against all observed heights answer different operator questions during incident review.
- `bft_round_change_density_avg` / `bft_round_change_density_avg_milli` / `bft_round_change_active_height_share_ppm`
  - keep as the normalized round-change density/share trio for handoff notes and alert text.
- `bft_round_change_backoff_total_ms` / `bft_round_change_backoff_avg_ms` / `bft_round_change_backoff_active_heights`
  - use together to distinguish how much backoff wall-clock time accumulated from how broadly that backoff spread across heights.
- `bft_round_change_backoff_active_height_rate_ppm` / `bft_round_change_backoff_active_observed_height_rate_ppm`
  - preserve both because backoff-active heights and backoff-active observed-height share should remain grep-stable across summaries.
- `bft_round_change_backoff_density_avg_ms` / `bft_round_change_backoff_density_avg_milli` / `bft_round_change_backoff_active_height_share_ppm`
  - keep as the normalized backoff intensity/share trio for dashboards and operator handoff.
- `bft_round_change_backoff_max_ms` / `bft_round_change_backoff_wall_share_ppm` / `bft_round_change_backoff_share_ppm`
  - preserve together because peak backoff and finality-share interpretations are often reviewed side by side during BFT incident triage; treat `bft_round_change_backoff_wall_share_ppm` as the descriptive field name and `bft_round_change_backoff_share_ppm` as its compatibility alias unless a future contract explicitly splits them.
- `bft_leader_missed_total` / `bft_leader_missed_max` / `bft_leader_missed_top_share_ppm`
  - use together to decide whether missed-proposal pressure is diffuse or concentrated on one proposer.
- `bft_leader_missed_active_validators` / `bft_leader_missed_active_validator_share_ppm`
  - use to distinguish single-validator trouble from lane-wide proposer health degradation.
- `bft_leader_missed_active_heights` / `bft_leader_missed_active_height_rate_ppm` / `bft_leader_missed_active_observed_height_rate_ppm`
  - read as the height-level blast-radius view before escalating to operator rotation or peer-health triage.
- `bft_leader_missed_density_avg` / `bft_leader_missed_density_avg_milli` / `bft_leader_missed_active_height_share_ppm`
  - keep as the normalized density/share trio for dashboards and handoff notes.
- `bft_leader_missed_proposals`
  - treat as the append-stable per-validator final vector; preserve ordering semantics and do not reinterpret it as a ranked/sorted list.
- `bft_double_vote_total` / `bft_auth_reject_*`
  - use as the trailing operator-visible BFT auth/safety cluster after the leader-missed proposer-health block.
- `bft_auth_reject_stale_total` / `bft_auth_reject_stale_nonce_total`
  - keep both append-stable for grep compatibility; treat `bft_auth_reject_stale_nonce_total` as the descriptive stale-nonce field and `bft_auth_reject_stale_total` as the compatibility alias. Today both resolve to the same stale-nonce rejection counter and should not be reinterpreted as distinct sources.
  - operator note: the block/round-progress `[bft]` log stream may still spell the same underlying signal with `auth_reject_stale` or `auth_reject_stale_nonce` tokens depending on the surface; treat those spellings as the same stale-nonce family unless and until a future contract explicitly splits them.

### Operator-visible summary template

A safe starter summary line for incident handoff is:

- `critical_wait_density_ppm=<n> critical_wait_peak_density_ppm=<n> critical_wait_active_heights=<n> critical_wait_active_height_rate_ppm=<n> critical_wait_active_observed_height_rate_ppm=<n> critical_wait_density_avg=<n> critical_wait_density_avg_milli=<n> critical_wait_active_height_share_ppm=<n> rollback_block_total=<n> rollback_active_heights=<n> rollback_block_rate=<n> rollback_block_rate_ppm=<n> rollback_active_height_rate_ppm=<n> rollback_active_observed_height_rate_ppm=<n> rollback_density_avg=<n> rollback_density_avg_milli=<n> rollback_active_height_share_ppm=<n> apply_error_total=<n> rollback_total=<n> apply_error_rollback_share_bps=<n> timeout_migrated_total=<n> recovery_error_rate=<n> bft_observed_heights=<n> bft_committed_heights=<n> bft_commit_observed_height_rate_ppm=<n> bft_skipped_height_total=<n> bft_skipped_observed_height_rate_ppm=<n> bft_round_change_total=<n> bft_round_change_per_height_ppm=<n> bft_round_change_active_heights=<n> bft_round_change_active_height_rate_ppm=<n> bft_round_change_active_observed_height_rate_ppm=<n> bft_round_change_density_avg=<n> bft_round_change_density_avg_milli=<n> bft_round_change_active_height_share_ppm=<n> bft_round_change_backoff_total_ms=<n> bft_round_change_backoff_avg_ms=<n> bft_round_change_backoff_active_heights=<n> bft_round_change_backoff_active_height_rate_ppm=<n> bft_round_change_backoff_active_observed_height_rate_ppm=<n> bft_round_change_backoff_density_avg_ms=<n> bft_round_change_backoff_density_avg_milli=<n> bft_round_change_backoff_active_height_share_ppm=<n> bft_round_change_backoff_max_ms=<n> bft_round_change_backoff_wall_share_ppm=<n> bft_round_change_backoff_share_ppm=<n> bft_leader_missed_total=<n> bft_leader_missed_max=<n> bft_leader_missed_top_share_ppm=<n> bft_leader_missed_active_validators=<n> bft_leader_missed_active_validator_share_ppm=<n> bft_leader_missed_active_heights=<n> bft_leader_missed_active_height_rate_ppm=<n> bft_leader_missed_active_observed_height_rate_ppm=<n> bft_leader_missed_density_avg=<n> bft_leader_missed_density_avg_milli=<n> bft_leader_missed_active_height_share_ppm=<n> bft_leader_missed_proposals=<vec> bft_double_vote_total=<n> bft_auth_reject_bad_sig_total=<n> bft_auth_reject_replay_total=<n> bft_auth_reject_stale_total=<n> bft_auth_reject_stale_nonce_total=<n>`

Keep field names verbatim so pager notes and release evidence remain grep-stable.

## 3. `trnm-worker-agent` operator-visible log lines

### Submit mode handoff line

When `trnm-worker-agent` runs in submit mode, the current operator-visible submit line is:

- `submitted=true submit_log=<path>`

Operational meaning:

- `submitted=true` tells the operator the submit branch actually executed.
- `submit_log=<path>` points to the persisted submit log file that should be attached during handoff/triage.

Current code emits the same token pair on stdout for the happy path and stderr for the failure path; the contract here is the token shape, not the stream choice.

This line is intentionally small and path-oriented.
If richer structured logging lands later, prefer adding fields rather than renaming these two tokens.

### Assigned-run summary line

When `trnm-worker-agent` finishes an assigned-run batch, the current operator-visible summary line is:

- `[agent] run-assigned processed=<n> skipped=<reason=count|none> ingress=<path> submit_log=<path> adapter=<name> adapter_retries=<n> adapter_backoff_ms=<n> adapter_timeout_ms=<n>`
  - if `skipped` is not `none`, preserve the current lexicographically ordered comma-separated `reason=count` encoding rather than reordering pairs by count or recency.

Operational meaning:

- `processed=<n>` is the number of requests advanced to the commit-queued path in this batch.
- `skipped=<reason=count|none>` is the compact skip-reason summary; preserve the `none` sentinel for zero-skip runs.
  When multiple skip reasons exist, keep the comma-separated `reason=count` pairs lexicographically ordered by reason so batch handoff notes remain grep-stable across reruns.
- `ingress=<path>` points to the ingress record file that was read and rewritten.
- `submit_log=<path>` points to the persisted submit log coupled to the batch.
- `adapter=<name>` plus the retry/backoff/timeout fields preserve the exact LLM-adapter policy context used during the run.

For operator handoff, keep this line append-stable and path-oriented. Additive fields are safer than renaming or reordering the existing tokens that batch triage may grep for.

## 4. Conservative rules for future changes

Until the unified dashboard/alert pack exists, apply these rules:

1. Prefer **adding** aliases/fields/metrics over renaming existing ones.
2. Treat the `trnm-rpc` health JSON body as append-stable.
3. Treat the `trnm-node` incident bundle names above as append-stable.
4. Treat `submitted=true submit_log=<path>` as the worker-agent minimum submit handoff line.
5. Treat `[agent] run-assigned ... submit_log=<path> ...` as the worker-agent minimum assigned-batch summary line.
6. If a new surface claims to supersede one of the above, keep a compatibility path or update this runbook in the same patch.

## 5. What this document does not claim

This document does **not** claim that TRNM already has:

- a complete node/rpc/worker/oracle/bridge unified metrics contract
- dashboards
- alert thresholds
- incident severity conventions
- replay attribution fully wired into observability

Those remain open P0 observability closure items per the blocker board and gap matrix.
