# Explorer Service Scaffold Runbook

## Purpose

This runbook describes the **operator-facing local scaffold** for TRNM's minimum explorer/read-service boundary.
It is intentionally small and should be treated as a **deployment placeholder**, not as a durable production indexer.

The current scaffold helps operators verify:

- a local process can expose a stable health endpoint,
- PID/log paths are predictable,
- run/stop/status mechanics are explicit,
- Day-1 read-service docs have one concrete execution path.

## Scope / non-goals

What this scaffold is:

- a local static HTTP service rooted at `trillionnium-rust/run/explorer-service/public`
- a predictable health target for operators (`/healthz`)
- a thin launch/status/stop loop around `python3 -m http.server`

What this scaffold is **not**:

- a durable indexer
- a replay pipeline
- a historical read-model
- an archive/read-replica strategy
- a production explorer backend

## Scripts

From `trillionnium-rust/`:

```bash
./scripts/v2/explorer_service_up.sh
./scripts/v2/explorer_service_status.sh
./scripts/v2/explorer_service_down.sh
```

## Default runtime contract

- bind host: `127.0.0.1`
- bind port: `8090`
- bind host: `127.0.0.1`
- bind port: `8090`
- health URL: `http://127.0.0.1:8090/healthz`
- PID file: `trillionnium-rust/run/explorer-service/explorer-service.pid`
- log file: `trillionnium-rust/run/explorer-service/explorer-service.log`
- public root: `trillionnium-rust/run/explorer-service/public`

## Environment overrides

The scaffold supports these environment variables:

- `EXPLORER_HOST`
- `EXPLORER_PORT`
- `EXPLORER_PUBLIC_BASE_URL`
- `EXPLORER_HEALTH_URL`

`EXPLORER_HOST` / `EXPLORER_PORT` control where the local static server binds.
`EXPLORER_PUBLIC_BASE_URL` controls the operator-facing base URL emitted in `health_url` / `index_url`, which is useful when the process binds to `0.0.0.0`, sits behind a reverse proxy, or is reached through port-forwarding.

Example:

```bash
EXPLORER_HOST=0.0.0.0 \
EXPLORER_PORT=18090 \
EXPLORER_PUBLIC_BASE_URL=https://read.trnm.example \
  ./scripts/v2/explorer_service_up.sh
```

If `EXPLORER_HEALTH_URL` is not provided, it defaults to `${EXPLORER_PUBLIC_BASE_URL}/healthz` when `EXPLORER_PUBLIC_BASE_URL` is set, otherwise `http://${EXPLORER_HOST}:${EXPLORER_PORT}/healthz`.

## Bring-up

```bash
cd trillionnium-rust
./scripts/v2/explorer_service_up.sh
./scripts/v2/explorer_service_status.sh
```

Expected healthy signals:

- `state=running`
- `health=ok`
- `pid_file=.../explorer-service.pid`
- `log_file=.../explorer-service.log`
- `public_dir=.../run/explorer-service/public`
- `bind_host=...`
- `bind_port=...`
- `health_url=http://.../healthz`
- `index_url=http://.../index.json`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`

If the PID file is malformed or empty, status reports `state=stale-pid` and also emits `pid_file_valid=false`.

## What gets served

The scaffold writes two static files before launching the HTTP server:

- `healthz`
- `index.json`

`healthz` reports that the scaffold is alive, but also marks `production_ready=false`.
`index.json` states clearly that the service is static-only and not a durable indexer/read-model, and now also exposes the current Day-1 read-only contract:

- `query-task/<task_id>`
- `query-events/<task_id>?limit=<n>`
- `query-capability-audit/<subject-or-token>`
- `query-normalized-audit-events/<task_id>?limit=<n>`

Additional contract markers carried in `index.json`:

- `query_events_default_limit=100`
- `query_events_max_limit=500`
- `write_paths_exposed=false`
- a note that historical queries remain bounded by current RPC retention until a durable indexer/archive strategy exists

## Failure interpretation

### `state=down`

Likely causes:

- the service has not been started,
- the process exited,
- the port is unreachable from the current host.

Action:

1. run `./scripts/v2/explorer_service_up.sh`
2. re-run `./scripts/v2/explorer_service_status.sh`
3. inspect the emitted `log_file` path

### `state=stale-pid`

Likely cause:

- PID file exists but the recorded process no longer does.

Action:

1. run `./scripts/v2/explorer_service_down.sh` to clear stale state
2. run `./scripts/v2/explorer_service_up.sh`
3. confirm `state=running`

### `health=down` while `state=running`

Likely causes:

- wrong `EXPLORER_HEALTH_URL`,
- bind host/port mismatch,
- local HTTP server is running but the expected path is not reachable.

Action:

1. verify `health_url` from `explorer_service_status.sh`
2. inspect `log_file`
3. fetch the URL directly with `curl`

## Shutdown

```bash
cd trillionnium-rust
./scripts/v2/explorer_service_down.sh
```

The down script attempts graceful termination first, then forces termination if the process does not exit within 5 seconds.
It also re-emits the same operator-facing contract fields as the up/status scripts so handoff/debug notes can still quote the canonical paths even when the service is already stopped:

- `pid_file=.../explorer-service.pid`
- `log_file=.../explorer-service.log`
- `public_dir=.../run/explorer-service/public`
- `bind_host=...`
- `bind_port=...`
- `health_url=http://.../healthz`
- `index_url=http://.../index.json`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`

Likewise, `explorer_service_up.sh` now emits the same `service_mode` / `production_ready` markers on success, "already running", and fail-fast exits, so operator notes can quote one consistent contract without having to run `status` first.

## Operator caution

Do **not** use this scaffold as evidence that TRNM has closed the public-mainnet explorer/indexer blocker.
It only proves that:

- one minimal service boundary is documented,
- one local operator flow exists,
- one health/log/PID contract is visible.

The remaining blocker still requires durable indexing, replay semantics, historical query policy, and a real deployment/SLO story.
