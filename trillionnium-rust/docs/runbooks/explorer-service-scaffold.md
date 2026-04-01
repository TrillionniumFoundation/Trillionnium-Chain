# Explorer Service Scaffold Runbook

This runbook describes the **operator-facing local scaffold** for TRNM's minimum explorer/read-service boundary.
It is intentionally small and should be treated as a **deployment placeholder**, not as a durable production indexer.

The current scaffold helps operators verify:

- where one minimal explorer-facing HTTP process would bind,
- where the process PID/log/public files live,
- what health probe path is expected,
- which upstream RPC read surface the placeholder expects,
- and how to bring it up/down without guessing hidden state.

## What this scaffold is

Today this scaffold provides only:

- a local static HTTP service rooted at `trillionnium-rust/run/explorer-service/public`
- a predictable health target for operators (`/healthz`)
- a minimal `index.json` describing the Day-1 read-only contract
- one operator-visible status contract for PID/log/public path inspection

## What this scaffold is not

This is **not**:

- a durable indexer
- a block/tx ingestion pipeline
- a historical read-model
- a production explorer backend
- proof that the public-mainnet explorer blocker is closed

## Bring-up

From the repo root:

```bash
./trillionnium-rust/scripts/v2/explorer_service_up.sh
./trillionnium-rust/scripts/v2/explorer_service_status.sh
./trillionnium-rust/scripts/v2/explorer_service_down.sh
```

Or from inside `trillionnium-rust/`:

```bash
./scripts/v2/explorer_service_up.sh
./scripts/v2/explorer_service_status.sh
./scripts/v2/explorer_service_down.sh
```

The scaffold writes/uses:

- PID file: `trillionnium-rust/run/explorer-service/explorer-service.pid`
- log file: `trillionnium-rust/run/explorer-service/explorer-service.log`
- public root: `trillionnium-rust/run/explorer-service/public`
- health file: `trillionnium-rust/run/explorer-service/public/healthz`
- index file: `trillionnium-rust/run/explorer-service/public/index.json`

## Runtime knobs

Optional environment variables:

- `EXPLORER_HOST` (default `127.0.0.1`)
- `EXPLORER_PORT` (default `8090`)
- `EXPLORER_PUBLIC_BASE_URL` (default `http://<host>:<port>`)
- `EXPLORER_HEALTH_URL` (default `<public_base_url>/healthz`)
- `EXPLORER_RPC_BASE_URL` (default `http://127.0.0.1:7777`)

`EXPLORER_PUBLIC_BASE_URL` controls the operator-facing base URL emitted in `health_url` / `index_url`, which is useful when the process binds to `0.0.0.0`, sits behind a reverse proxy, or is reached through port-forwarding.

If you need a reverse-proxy-facing health URL different from the local bind target, set `EXPLORER_HEALTH_URL` explicitly.

Example:

```bash
cd trillionnium-rust
EXPLORER_HOST=0.0.0.0 \
EXPLORER_PORT=18090 \
EXPLORER_PUBLIC_BASE_URL=https://explorer.local.trnm.example \
EXPLORER_HEALTH_URL=https://explorer.local.trnm.example/healthz \
EXPLORER_RPC_BASE_URL=http://127.0.0.1:7777 \
  ./scripts/v2/explorer_service_up.sh
```

## Expected status output

After a successful start, run:

```bash
./scripts/v2/explorer_service_up.sh
./scripts/v2/explorer_service_status.sh
```

The status output should include the operator contract fields below:

- `state=running`
- `pid=<pid>`
- `pid_file=.../explorer-service.pid`
- `log_file=.../explorer-service.log`
- `public_dir=.../run/explorer-service/public`
- `health_file=.../run/explorer-service/public/healthz`
- `index_file=.../run/explorer-service/public/index.json`
- `bind_host=...`
- `bind_port=...`
- `public_base_url=http://...`
- `health_url=http://.../healthz`
- `local_health_url=http://<bind_host>:<bind_port>/healthz`
- `index_url=http://.../index.json`
- `rpc_base_url=http://...`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`
- `health=ok`
- `health_probe=active`
- `health_probe_url=<the exact URL status checked>`

If the runtime contract is invalid, `explorer_service_status.sh` exits non-zero and prints `state=invalid-config` plus `config_error=...` and `health_probe_url=invalid-config` so operators can see the probe never ran.

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

1. inspect `health_probe_url` first to see which exact endpoint `explorer_service_status.sh` tried
2. verify both `health_url` and `local_health_url` from `explorer_service_status.sh`
3. inspect `log_file`
4. fetch `local_health_url` directly with `curl` first, then debug the public/reverse-proxy URL separately if needed

If `state!=running`, treat `health=unknown` as expected and fix the process/PID state first instead of debugging the HTTP probe path.

## Shutdown

```bash
cd trillionnium-rust
./scripts/v2/explorer_service_down.sh
```

The down script attempts graceful termination first, then forces termination if the process does not exit within 5 seconds.
It also re-emits the same operator-facing contract fields as the up/status scripts so handoff/debug notes can still quote the canonical paths even when the service is already stopped. The shutdown path now also emits the terminal state markers that automation can key on without having to call `status` again:

- `state=down`
- `health=unknown`
- `health_probe=not-run-state-down`
- `pid_file=.../explorer-service.pid`
- `log_file=.../explorer-service.log`
- `public_dir=.../run/explorer-service/public`
- `health_file=.../run/explorer-service/public/healthz`
- `index_file=.../run/explorer-service/public/index.json`
- `bind_host=...`
- `bind_port=...`
- `public_base_url=http://...`
- `health_url=http://.../healthz`
- `local_health_url=http://<bind_host>:<bind_port>/healthz`
- `index_url=http://.../index.json`
- `rpc_base_url=http://...`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`

Likewise, `explorer_service_up.sh` now emits the same `service_mode` / `production_ready` markers plus `public_base_url=...`, `rpc_base_url=...`, and `local_health_url=...` on success, "already running", and fail-fast exits, so operator notes can quote one consistent contract without having to run `status` first. Its startup gate intentionally probes the local bind target rather than `EXPLORER_PUBLIC_BASE_URL`, so a reverse-proxy-facing public URL can still differ from the local loopback/host bind without breaking the operator bring-up check.

## Operator caution

Do **not** use this scaffold as evidence that TRNM has closed the public-mainnet explorer/indexer blocker.
It only proves that:

- one minimal service boundary is documented,
- one local operator flow exists,
- one health/log/PID contract is visible.

The remaining blocker still requires durable indexing, replay semantics, historical query policy, and a real deployment/SLO story.
