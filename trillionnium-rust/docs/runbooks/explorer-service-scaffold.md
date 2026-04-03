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

## What still closes the Rank 1 blocker

Treat this runbook as the **operator-facing placeholder edge** only.
Closing the actual Rank 1 read-surface / indexer / explorer blocker still requires the repo to carry explicit evidence for all of the following:

1. a **durable indexer pipeline** rather than static files backed only by the current RPC window
2. an explicit **historical read-model / retention policy** for replay, archive, and bounded-vs-durable query semantics
3. an **explorer backend/API** that is no longer just the local scaffold described here
4. an operator packet covering **deployment, replay/recovery, and SLO ownership** for that non-placeholder read service

For the current task decomposition and exit criteria, cross-check:

- `trillionnium-rust/docs/release/TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_LAUNCH_COUNTDOWN_2026-04-03.md`

If a handoff note, incident ticket, or release review cites this scaffold alone as proof that explorer/indexer closure exists, treat that as **insufficient evidence** and escalate the missing durable-read artifacts explicitly.

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
- suggested env file: `trillionnium-rust/run/explorer-service/explorer-service.env`
- public root: `trillionnium-rust/run/explorer-service/public`
- health file: `trillionnium-rust/run/explorer-service/public/healthz`
- index file: `trillionnium-rust/run/explorer-service/public/index.json`

## Runtime knobs

Optional environment variables:

- `EXPLORER_HOST` (default `127.0.0.1`)
- `EXPLORER_PORT` (default `8090`)
- `EXPLORER_PUBLIC_BASE_URL` (default `http://<host>:<port>`, or `http://[<ipv6-host>]:<port>` when `EXPLORER_HOST` is IPv6)
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

## Minimum operator deployment skeleton

This scaffold is still local/static-only, but operators should use one repeatable deployment shape instead of ad-hoc shell history.
A minimal Day-1 handoff can be expressed as:

1. keep the process bound to a predictable host/port,
2. persist runtime knobs in one env file,
3. place any reverse proxy in front of `EXPLORER_PUBLIC_BASE_URL`,
4. keep the startup/liveness probe pointed at the local bind target unless you are explicitly testing proxy reachability.

### Minimum handoff evidence packet

To keep the current scaffold useful as an **operator-facing deployment placeholder** without overstating blocker closure, capture one small evidence packet whenever you bring it up for rehearsal or handoff:

1. the exact env file values used for `EXPLORER_HOST`, `EXPLORER_PORT`, `EXPLORER_PUBLIC_BASE_URL`, `EXPLORER_HEALTH_URL`, and `EXPLORER_RPC_BASE_URL`
2. one `./scripts/v2/explorer_service_status.sh` output block showing `state`, `health_url`, `local_health_url`, `index_url`, and `rpc_base_url`
3. one fetch of `/index.json` proving the static scaffold is serving the declared Day-1 read-only contract markers
4. one explicit note that this evidence **does not** prove durable indexer / historical read-model / production explorer-backend closure

This packet is intentionally narrow: it closes the question "what exact deployment-path evidence should an operator attach for the current placeholder service?" without claiming that the Rank 1 explorer/indexer blocker is solved.

Suggested env file (`trillionnium-rust/run/explorer-service/explorer-service.env`):

> On first successful/local bring-up, `explorer_service_up.sh` will create this file automatically if it does not already exist, using the current runtime contract values. It never overwrites an existing env file, so operator-local edits remain the source of truth.
>
> The script default remains `EXPLORER_PORT=8090` when no override is provided. The sample below is an explicit reverse-proxy-facing example that pins the scaffold to `18090`; if you bring the scaffold up with no port override, the generated env file will carry `8090` instead.

```bash
EXPLORER_HOST=127.0.0.1
EXPLORER_PORT=18090
EXPLORER_PUBLIC_BASE_URL=https://explorer.trnm.example
EXPLORER_HEALTH_URL=https://explorer.trnm.example/healthz
EXPLORER_RPC_BASE_URL=http://127.0.0.1:7777
```

Suggested bring-up from the repo root:

```bash
./trillionnium-rust/scripts/v2/explorer_service_up.sh
./trillionnium-rust/scripts/v2/explorer_service_status.sh
```

If `trillionnium-rust/run/explorer-service/explorer-service.env` exists, all three scaffold scripts now auto-load it before computing their runtime contract, so operator-local bind/proxy settings persist across `up`, `status`, and `down` without needing a separate `set -a; source ...` step.

### Minimal service-manager skeleton

For a Day-1 operator handoff, keep one explicit service-manager shape so the scaffold is restarted the same way every time.
A minimal `systemd` unit can look like this:

```ini
[Unit]
Description=TRNM explorer service scaffold
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/trnm/trillionnium-rust
EnvironmentFile=/opt/trnm/trillionnium-rust/run/explorer-service/explorer-service.env
ExecStart=/opt/trnm/trillionnium-rust/scripts/v2/explorer_service_up.sh
ExecStop=/opt/trnm/trillionnium-rust/scripts/v2/explorer_service_down.sh
ExecStartPost=/opt/trnm/trillionnium-rust/scripts/v2/explorer_service_status.sh
RemainAfterExit=yes
User=trnm
Group=trnm

[Install]
WantedBy=multi-user.target
```

Because `explorer_service_up.sh` launches the local HTTP server in the background and then exits, the example unit uses `Type=oneshot` + `RemainAfterExit=yes` so systemd tracks the scaffold lifecycle correctly instead of treating the helper script's quick exit as an unexpected service stop.

### Minimal reverse-proxy skeleton

When operators keep the scaffold bound to loopback and expose it via `EXPLORER_PUBLIC_BASE_URL`, use one explicit proxy shape instead of ad-hoc port forwarding.
A minimal `nginx` location can look like this:

```nginx
server {
    listen 443 ssl;
    server_name explorer.trnm.example;

    location / {
        proxy_pass http://127.0.0.1:18090/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /healthz {
        proxy_pass http://127.0.0.1:18090/healthz;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
```

Recommended pairing for that shape:

- keep `EXPLORER_HOST=127.0.0.1`
- keep `EXPLORER_PORT=18090`
- set `EXPLORER_PUBLIC_BASE_URL=https://explorer.trnm.example`
- set `EXPLORER_HEALTH_URL=https://explorer.trnm.example/healthz`
- leave the scaffold startup/liveness gate pointed at `local_health_url=http://127.0.0.1:18090/healthz`

This keeps the operator-facing/public URL distinct from the local probe target while preserving the same static-only read contract.

Use this only as an operator scaffold, not as proof of production-readiness:

- keep `WorkingDirectory` pinned to the checked-out `trillionnium-rust/` tree so PID/log/public paths stay aligned with the runbook
- keep the env file outside shell history and review it before `systemctl start` / `restart`
- use `ExecStartPost` output as the ticket/handoff artifact so the emitted `public_base_url`, `health_url`, `local_health_url`, and `rpc_base_url` are captured from one source of truth
- if you are not using `systemd`, preserve the same shape anyway: fixed working directory, one env file, explicit up/down/status lifecycle

Operator notes for this placeholder deployment shape:

- prefer `EXPLORER_HOST=127.0.0.1` when a reverse proxy terminates external traffic; only bind `0.0.0.0` if the host/network policy really requires direct exposure
- treat `EXPLORER_PUBLIC_BASE_URL` as the public/operator-facing URL and `local_health_url` as the local liveness target; they may differ legitimately
- keep the env file, emitted `pid_file`, and emitted `log_file` together in handoff notes so the next operator can restart or roll back without guessing hidden shell state; the scripts auto-load that env file when present
- if the proxy layer is changed, re-run `explorer_service_status.sh` and quote both `health_url` and `local_health_url` in the ticket/handoff note
- keep the reverse proxy dumb: forward `/` and `/healthz`, but do not rewrite the read-contract paths or imply historical/archive semantics the scaffold does not provide

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
- `env_file=.../explorer-service.env`
- `public_dir=.../run/explorer-service/public`
- `health_file=.../run/explorer-service/public/healthz`
- `index_file=.../run/explorer-service/public/index.json`
- `bind_host=...`
- `bind_port=...`
- `public_base_url=http://...`
- `health_url=http://.../healthz`
- `local_health_url=http://<local_probe_host>:<bind_port>/healthz` (`127.0.0.1` when `EXPLORER_HOST=0.0.0.0`, `[::1]` when `EXPLORER_HOST=::`, otherwise the bind host)
- `index_url=http://.../index.json`
- `rpc_base_url=http://...`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`
- `read_contract_mode=read-only`
- `read_contract_source=rpc-read-surface`
- `day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>`
- `query_events_default_limit=100`
- `query_events_max_limit=500`
- `write_paths_exposed=false`
- `historical_query_scope=rpc-retention-bounded`
- `durability_boundary=ephemeral-rpc-window-only`
- `archive_strategy=not-configured-static-scaffold`
- `read_replica_strategy=not-configured-static-scaffold`
- `health=ok`
- `health_probe=active`
- `health_probe_url=<the exact public/reverse-proxy-facing URL status checked>`
- `local_health=ok`
- `local_health_probe=active`
- `local_health_probe_url=http://<bind_host>:<bind_port>/healthz`

If the runtime contract is invalid, `explorer_service_status.sh` exits non-zero and prints `state=invalid-config` plus `config_error=...` and `health_probe_url=invalid-config` so operators can see the probe never ran.

If `explorer_service_up.sh` fails its post-launch liveness check, it now removes the just-written PID file before exiting so the next operator status check sees a clean `state=down` instead of a misleading startup-generated `stale-pid` artifact. When `curl` is available, that liveness check now probes the scaffold's local bind target (`http://<bind_host>:<bind_port>/healthz`) instead of only checking that the `python3 -m http.server` process is still alive.

## What gets served

The scaffold writes two static files before launching the HTTP server:

- `healthz`
- `index.json`

`healthz` reports that the scaffold is alive, but also marks `production_ready=false`.
`index.json` states clearly that the service is static-only and not a durable indexer/read-model, and now records both `health_url` and `local_health_url` alongside `rpc_base_url`, so operators can preserve the reverse-proxy-facing endpoint and the local bind probe in the same evidence packet. It now exposes the current Day-1 read-only contract:

- `query-task/<task_id>`
- `query-events/<task_id>?limit=<n>`
- `query-capability-audit/<subject-or-token>`
- `query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>`

Additional contract markers carried in `index.json`:

- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`
- `rpc_base_url=<upstream-rpc-read-surface>`
- `query_events_default_limit=100`
- `query_events_max_limit=500`
- `write_paths_exposed=false`
- `historical_query_scope=rpc-retention-bounded`
- `durability_boundary=ephemeral-rpc-window-only`
- `archive_strategy=not-configured-static-scaffold`
- `read_replica_strategy=not-configured-static-scaffold`
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

If `state!=running`, treat `health=unknown` and `local_health=unknown` as expected and fix the process/PID state first instead of debugging the HTTP probe path.

A useful operator interpretation rule now is:

- `health=down` + `local_health=ok` usually points to reverse-proxy/public-URL drift while the local scaffold is still alive
- `health=down` + `local_health=down` usually means the local bind target itself is broken or the process is serving the wrong path

## Shutdown

```bash
cd trillionnium-rust
./scripts/v2/explorer_service_down.sh
```

The down script attempts graceful termination first, then forces termination if the process does not exit within 5 seconds.
It also re-emits the same operator-facing contract fields as the up/status scripts, including the Day-1 read-contract markers, so handoff/debug notes can still quote the canonical paths and read-only boundary even when the service is already stopped. The shutdown path now also emits the terminal state markers that automation can key on without having to call `status` again:

- `state=down`
- `health=unknown`
- `health_probe=not-run-state-down`
- `health_probe_url=not-run-state-down`
- `local_health=unknown`
- `local_health_probe=not-run-state-down`
- `local_health_probe_url=http://<bind_host>:<bind_port>/healthz` only when running; down/invalid-config exits emit `not-run-state-down` / `invalid-config` markers instead
- `pid_file=.../explorer-service.pid`
- `log_file=.../explorer-service.log`
- `env_file=.../explorer-service.env`
- `public_dir=.../run/explorer-service/public`
- `health_file=.../run/explorer-service/public/healthz`
- `index_file=.../run/explorer-service/public/index.json`
- `bind_host=...`
- `bind_port=...`
- `public_base_url=http://...`
- `health_url=http://.../healthz`
- `local_health_url=http://<local_probe_host>:<bind_port>/healthz` (`127.0.0.1` when `EXPLORER_HOST=0.0.0.0`, `[::1]` when `EXPLORER_HOST=::`, otherwise the bind host)
- `index_url=http://.../index.json`
- `rpc_base_url=http://...`
- `service_mode=operator-facing-static-scaffold`
- `production_ready=false`
- `read_contract_mode=read-only`
- `read_contract_source=rpc-read-surface`
- `day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>`
- `query_events_default_limit=100`
- `query_events_max_limit=500`
- `write_paths_exposed=false`
- `historical_query_scope=rpc-retention-bounded`
- `durability_boundary=ephemeral-rpc-window-only`
- `archive_strategy=not-configured-static-scaffold`
- `read_replica_strategy=not-configured-static-scaffold`

Likewise, `explorer_service_up.sh` now emits the same `service_mode` / `production_ready` markers plus `public_base_url=...`, `rpc_base_url=...`, and `local_health_url=...` on success, "already running", and fail-fast exits, so operator notes can quote one consistent contract without having to run `status` first. Its startup gate intentionally probes the local bind target rather than `EXPLORER_PUBLIC_BASE_URL`, so a reverse-proxy-facing public URL can still differ from the local loopback/host bind without breaking the operator bring-up check.

## Operator caution

Do **not** use this scaffold as evidence that TRNM has closed the public-mainnet explorer/indexer blocker.
It only proves that:

- one minimal service boundary is documented,
- one local operator flow exists,
- one health/log/PID contract is visible.

The remaining blocker still requires durable indexing, replay semantics, historical query policy, and a real deployment/SLO story.

Treat `durability_boundary=ephemeral-rpc-window-only` as a fail-closed reminder that this scaffold has no persisted cursor/checkpoint/read-model state of its own: once the upstream RPC retention window no longer carries a record, the scaffold has no independent durability claim to fall back on.
