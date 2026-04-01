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
- health URL: `http://127.0.0.1:8090/healthz`
- PID file: `trillionnium-rust/run/explorer-service/explorer-service.pid`
- log file: `trillionnium-rust/run/explorer-service/explorer-service.log`
- public root: `trillionnium-rust/run/explorer-service/public`
- health file: `trillionnium-rust/run/explorer-service/public/healthz`
- index file: `trillionnium-rust/run/explorer-service/public/index.json`

## Environment overrides

The scaffold supports these environment variables:

- `EXPLORER_HOST`
- `EXPLORER_PORT`
- `EXPLORER_PUBLIC_BASE_URL`
- `EXPLORER_HEALTH_URL`
- `EXPLORER_RPC_BASE_URL`

`EXPLORER_HOST` / `EXPLORER_PORT` control where the local static server binds.
`EXPLORER_PUBLIC_BASE_URL` controls the operator-facing base URL emitted in `health_url` / `index_url`, which is useful when the process binds to `0.0.0.0`, sits behind a reverse proxy, or is reached through port-forwarding.
`EXPLORER_RPC_BASE_URL` records which RPC read surface this scaffold is documenting; it defaults to `http://127.0.0.1:7777` and is emitted by the up/status/down scripts as `rpc_base_url=...` so handoff notes can name the expected upstream read source explicitly.

Fail-closed config guardrails now apply before start/status/down execution:

- `EXPLORER_HOST` must not be empty
- `EXPLORER_PORT` must be an integer in `[1, 65535]`

If those checks fail, the scripts stop immediately instead of attempting a misleading partial launch or reporting status for an invalid bind target.

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
- `health_file=.../run/explorer-service/public/healthz`
- `index_file=.../run/explorer-service/public/index.json`
- `bind_host=...`
- `bind_port=...`
- `health_url=http://.../healthz`
- `index_url=http://.../index.json`
- `rpc_base_url=http://...`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`

If the PID file is malformed or empty, status reports `state=stale-pid` and also emits `pid_file_valid=false`.
If `curl` is unavailable on the host, the status script leaves active probing disabled and reports `health=unknown` instead of forcing a false negative.
The status script now probes `health_url` only when `state=running`, so operators do not get a misleading `health=ok` from an unrelated process that happens to answer on the same URL while the scaffold PID is absent or stale.
If `explorer_service_up.sh` fails its post-launch liveness check, it now removes the just-written PID file before exiting so the next operator status check sees a clean `state=down` instead of a misleading startup-generated `stale-pid` artifact. When `curl` is available, that liveness check now probes the scaffold's local bind target (`http://<bind_host>:<bind_port>/healthz`) instead of only checking that the `python3 -m http.server` process is still alive.

## What gets served

The scaffold writes two static files before launching the HTTP server:

- `healthz`
- `index.json`

`healthz` reports that the scaffold is alive, but also marks `production_ready=false`.
`index.json` states clearly that the service is static-only and not a durable indexer/read-model, and also records `rpc_base_url` so operators can see which upstream RPC read surface the scaffold expects. It now exposes the current Day-1 read-only contract:

- `query-task/<task_id>`
- `query-events/<task_id>?limit=<n>`
- `query-capability-audit/<subject-or-token>`
- `query-normalized-audit-events/<task_id>?limit=<n>`

Additional contract markers carried in `index.json`:

- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`
- `rpc_base_url=<upstream-rpc-read-surface>`
- `query_events_default_limit=100`
- `query_events_max_limit=500`
- `write_paths_exposed=false`
- a note that historical queries remain bounded by current RPC retention until a durable indexer/archive strategy exists

## Failure interpretation

### `state=down`

Likely causes:

- the service has not been started,
- the process exited,
- the port is unreachable from the current host,
- `python3` is unavailable on the host, so the scaffold refused to start.

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

If `state!=running`, treat `health=unknown` as expected and fix the process/PID state first instead of debugging the HTTP probe path.

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
- `health_file=.../run/explorer-service/public/healthz`
- `index_file=.../run/explorer-service/public/index.json`
- `bind_host=...`
- `bind_port=...`
- `health_url=http://.../healthz`
- `index_url=http://.../index.json`
- `rpc_base_url=http://...`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`

Likewise, `explorer_service_up.sh` now emits the same `service_mode` / `production_ready` markers plus `rpc_base_url=...` on success, "already running", and fail-fast exits, so operator notes can quote one consistent contract without having to run `status` first. Its startup gate intentionally probes the local bind target rather than `EXPLORER_PUBLIC_BASE_URL`, so a reverse-proxy-facing public URL can still differ from the local loopback/host bind without breaking the operator bring-up check.

## Operator caution

Do **not** use this scaffold as evidence that TRNM has closed the public-mainnet explorer/indexer blocker.
It only proves that:

- one minimal service boundary is documented,
- one local operator flow exists,
- one health/log/PID contract is visible.

The remaining blocker still requires durable indexing, replay semantics, historical query policy, and a real deployment/SLO story.
