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

## Environment overrides

The scaffold supports these environment variables:

- `EXPLORER_HOST`
- `EXPLORER_PORT`
- `EXPLORER_HEALTH_URL`

Example:

```bash
EXPLORER_HOST=0.0.0.0 EXPLORER_PORT=18090 \
  ./scripts/v2/explorer_service_up.sh
```

If `EXPLORER_HEALTH_URL` is not provided, it defaults to `http://${EXPLORER_HOST}:${EXPLORER_PORT}/healthz`.

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
- `health_url=http://.../healthz`

## What gets served

The scaffold writes two static files before launching the HTTP server:

- `healthz`
- `index.json`

`healthz` reports that the scaffold is alive, but also marks `production_ready=false`.
`index.json` states clearly that the service is static-only and not a durable indexer/read-model.

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

## Operator caution

Do **not** use this scaffold as evidence that TRNM has closed the public-mainnet explorer/indexer blocker.
It only proves that:

- one minimal service boundary is documented,
- one local operator flow exists,
- one health/log/PID contract is visible.

The remaining blocker still requires durable indexing, replay semantics, historical query policy, and a real deployment/SLO story.
