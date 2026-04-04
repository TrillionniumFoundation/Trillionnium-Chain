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

### Rank 1 closure cross-check (fail-closed)

Use the following table before labeling any explorer/indexer milestone as "closed":

| Rank 1 DoD item | Can the current scaffold evidence satisfy it by itself? | Why / what is still missing |
| --- | --- | --- |
| Day-1 minimum public read surface frozen | **Partially at best** | The scaffold can quote the current Day-1 read-only contract from `index.json`, but the real truth-source remains the release docs and contract tests, not the static placeholder itself. |
| durable indexer pipeline exists | **No** | The scaffold serves static files and has no ingestion, replay cursor, checkpoint, or persistence path of its own. |
| historical query / storage policy explicit | **No** | The scaffold can restate that history is bounded by the current RPC retention window, but it does not define or implement a durable retention/archive policy. |
| explorer backend/API no longer just scaffold | **No** | This runbook explicitly describes a local operator-facing placeholder rather than a production explorer backend/API. |
| operator deployment + replay + SLO packet exists | **Not fully** | This runbook covers the placeholder bring-up packet only; a non-placeholder service still needs deployment, replay/recovery, and SLO ownership evidence tied to the durable read path. |

Default interpretation: if any row above remains `No`, `Not fully`, or `Partially at best`, the Rank 1 blocker remains open.

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
   - that status block now also emits `deployment_evidence_scope=placeholder-only`, `rank1_read_surface_blocker=still-open`, `durable_indexer_status=not-implemented-in-this-scaffold`, `historical_query_scope=rpc-retention-bounded`, `durability_boundary=ephemeral-rpc-window-only`, `archive_strategy=not-configured-static-scaffold`, `read_replica_strategy=not-configured-static-scaffold`, `durable_read_anchor_complete=false`, `durable_read_anchor_missing_count=6`, `durable_read_anchor_missing_fields=...`, and the flat `durable_read_anchor_*=` placeholders; copy them verbatim into the handoff note instead of paraphrasing
3. one fetch of `/index.json` proving the static scaffold is serving the declared Day-1 read-only contract markers, including the flat `historical_query_scope`, `durability_boundary`, `archive_strategy`, and `read_replica_strategy` fields that mirror the CLI/status contract
4. one explicit note that this evidence **does not** prove durable indexer / historical read-model / production explorer-backend closure

This packet is intentionally narrow: it closes the question "what exact deployment-path evidence should an operator attach for the current placeholder service?" without claiming that the Rank 1 explorer/indexer blocker is solved.

### Deterministic evidence capture commands

Use one repeatable capture sequence so the handoff note is built from emitted contract fields rather than shell memory or paraphrase.

Preferred helper (captures status + served/static index + summary into one timestamped packet and fails closed unless the placeholder is actually healthy):

```bash
# from repo root
./trillionnium-rust/scripts/v2/capture_explorer_scaffold_handoff.sh
```

By default this writes a packet under `trillionnium-rust/run/explorer-service/handoff-<timestamp>/` containing:

- `status.txt`
- `index.json`
- `summary.txt`

`summary.txt` is intentionally operator-facing rather than generic bookkeeping only: besides the output paths and template pointer, it freezes the current `service_mode`, `production_ready`, `bind_host`, `bind_port`, `env_file`, `pid_file`, `log_file`, `public_dir`, `health_file`, `index_file`, `public_base_url`, `health_url`, `local_health_url`, the actual probe results (`health`, `health_probe`, `health_probe_url`, `local_health`, `local_health_probe`, `local_health_probe_url`), `index_url`, `rpc_base_url`, the placeholder scaffold truth-source pointer (`truth_source_scaffold_runbook=trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`), the fail-closed Day-1 read-surface markers (`read_contract_mode`, `read_contract_source`, `day1_surface`, `query_events_default_limit`, `query_events_max_limit`, `write_paths_exposed`, `historical_query_scope`, `durability_boundary`, `archive_strategy`, `read_replica_strategy`), the durable-read-anchor placeholders, and the canonical bring-up / status / rollback / index-fetch commands. This keeps the placeholder deployment path and public-read boundary reproducible in one file instead of forcing the next operator to reconstruct local bind/probe details or limit/readonly semantics from `status.txt` by hand, and makes the placeholder/non-production boundary explicit even if only `summary.txt` gets pasted into a ticket or handoff note.

If you need a deterministic destination for a ticket or operator bundle, pass it explicitly:

```bash
./trillionnium-rust/scripts/v2/capture_explorer_scaffold_handoff.sh \
  --output-dir trillionnium-rust/run/explorer-service/handoff-ticket-001
```

Manual fallback if you are debugging the helper itself:

```bash
# from repo root
./trillionnium-rust/scripts/v2/explorer_service_up.sh \
  | tee trillionnium-rust/run/explorer-service/handoff-up.txt

./trillionnium-rust/scripts/v2/explorer_service_status.sh \
  | tee trillionnium-rust/run/explorer-service/handoff-status.txt

curl -fsS http://127.0.0.1:${EXPLORER_PORT:-8090}/index.json \
  | tee trillionnium-rust/run/explorer-service/handoff-index.json
```

If the public/reverse-proxy URL is the evidence target, capture that separately instead of replacing the local proof:

```bash
curl -fsS "${EXPLORER_PUBLIC_BASE_URL:-http://127.0.0.1:${EXPLORER_PORT:-8090}}/index.json" \
  | tee trillionnium-rust/run/explorer-service/handoff-public-index.json
```

Fail-closed capture rules:

- the helper refuses to emit a packet unless `explorer_service_status.sh` reports `state=running`, `health=ok`, `local_health=ok`, `deployment_evidence_scope=placeholder-only`, `rank1_read_surface_blocker=still-open`, `durable_indexer_status=not-implemented-in-this-scaffold`, and `durable_read_anchor_complete=false`
- keep the local `status.txt`/`handoff-status.txt` even when the public fetch is the ticket artifact; it preserves the bind/probe boundary that the public URL alone cannot prove
- if the public fetch fails but the local fetch succeeds, keep the note scoped to placeholder deployment evidence and classify the proxy/public path separately instead of rewriting the scaffold as down
- if the local fetch fails, do not substitute a browser screenshot or paraphrased JSON fields; preserve the failing command/output and treat the packet as incomplete
- if `EXPLORER_PORT` / `EXPLORER_PUBLIC_BASE_URL` are being sourced from `explorer-service.env`, do not retype them by hand mid-capture; let the scripts emit the canonical values first, then reuse those values in the note

If you want a copy/paste ticket/handoff skeleton instead of assembling the note manually, use:

- `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`

Template selection shortcut for operators:

- if `deployment_evidence_scope=placeholder-only`, `service_mode=operator-facing-static-scaffold`, or any durable-read anchor is still `missing-*` / `placeholder-*` / `not-configured-*`, stay on the scaffold handoff template
- only switch to the durable-service template after the deployment boundary is no longer scaffold-based, all 6 durable-read anchors have real values, and replay / restore / lag evidence exists in the same note
- do not mix placeholder script output into a durable-service handoff packet unless it is explicitly labeled as historical or comparison-only evidence

### What must exist before this scaffold can be retired

Do not replace this scaffold with a so-called "real" explorer/read service unless the handoff packet names all of the following durable-read anchors explicitly:

1. `ingestion_source=` — the canonical source of indexed data (`rpc-pull`, `event-stream`, `block-replay`, or a documented mixed mode)
2. `checkpoint_store=` — where the durable cursor/checkpoint is persisted
3. `replay_start_anchor=` — the exact genesis/checkpoint/archive anchor used for rebuilds
4. `retention_scope=` — whether queries are `rpc-window-bounded`, `durable-hot`, or `durable+archive`
5. `archive_owner=` — which component/operator owns long-horizon historical retention and restore
6. `lag_slo=` — the freshness/index-lag budget the operator is actually promising

Fail-closed rule: if any field above is missing, treat the deployment as another placeholder edge, not as durable indexer / historical read-model closure.

If you are preparing the first non-placeholder handoff packet rather than another scaffold-only note, start from:

- `trillionnium-rust/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md`

### Handoff template selection quick check

Before reusing any explorer/read-service evidence in a ticket, release review, or operator handoff note, classify the packet with this fail-closed matrix:

| observed evidence shape | allowed template | boundary decision |
| --- | --- | --- |
| any evidence comes directly from `capture_explorer_scaffold_handoff.sh`, `explorer_service_status.sh`, or this scaffold runbook, and `deployment_evidence_scope=placeholder-only` remains intact | `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | keep the packet placeholder-only; do not upgrade it by hand |
| `deployment_evidence_scope` is missing entirely, or appears only in prose rather than as a preserved packet field | `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | boundary is mechanically undecidable, so fail closed to placeholder-only |
| `service_mode` is still `operator-facing-static-scaffold` even if the service is reverse-proxied or wrapped by systemd | `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | deployment shape is still scaffold-boundary only |
| any of the 6 durable-read anchors (`ingestion_source`, `checkpoint_store`, `replay_start_anchor`, `retention_scope`, `archive_owner`, `lag_slo`) is missing, placeholder, or inferred from future intent rather than current evidence | `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | durable read boundary is not established |
| non-placeholder deployment evidence exists **and** all 6 durable-read anchors have real values **and** replay / restore / lag evidence is attached in the same packet | `trillionnium-rust/docs/release/TRNM_DURABLE_READ_SERVICE_HANDOFF_TEMPLATE_2026-04-04.md` | eligible for durable-read-service review |

Fail-closed rule: changing only the prose around a scaffold packet does not change the packet class. If the evidence still originates from scaffold-only scripts or still carries placeholder markers, the handoff stays placeholder-only.

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
- `deployment_evidence_scope=placeholder-only`
- `rank1_read_surface_blocker=still-open`
- `durable_indexer_status=not-implemented-in-this-scaffold`
- `durable_read_anchor_complete=false`
- `durable_read_anchor_missing_count=6`
- `durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo`
- `durable_read_anchor_ingestion_source=missing-placeholder-scaffold`
- `durable_read_anchor_checkpoint_store=missing-placeholder-scaffold`
- `durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold`
- `durable_read_anchor_retention_scope=rpc-window-bounded`
- `durable_read_anchor_archive_owner=missing-placeholder-scaffold`
- `durable_read_anchor_lag_slo=missing-placeholder-scaffold`
- `health=ok`
- `health_probe=active`
- `health_probe_url=<the exact public/reverse-proxy-facing URL status checked>`
- `local_health=ok`
- `local_health_probe=active`
- `local_health_probe_url=http://<bind_host>:<bind_port>/healthz`

If the runtime contract is invalid, `explorer_service_status.sh` exits non-zero and prints `state=invalid-config` plus `config_error=...` and `health_probe_url=invalid-config` so operators can see the probe never ran.

If `explorer_service_up.sh` fails its post-launch liveness check, it now removes the just-written PID file before exiting so the next operator status check sees a clean `state=down` instead of a misleading startup-generated `stale-pid` artifact. When `curl` is available, that liveness check now probes the scaffold's local bind target (`http://<bind_host>:<bind_port>/healthz`) instead of only checking that the `python3 -m http.server` process is still alive. In that specific startup-failure path, the script also leaves `health_probe=not-run-startup-local-only` / `health_probe_url=not-run-startup-local-only` so operators do not misread the failure as evidence that the public/reverse-proxy-facing `health_url` was already probed; only `local_health_probe=startup-local-health-probe-failed` and `local_health_probe_url=<local bind target>` should be treated as exercised.

## What gets served

The scaffold writes two static files before launching the HTTP server:

- `healthz`
- `index.json`

`healthz` reports that the scaffold is alive, preserves the minimum health probe shape (`ok=true`, `service`, `ts_unix_ms`, `version=1`), and also marks `production_ready=false` so operators do not over-read the placeholder as durable read-model closure.
`index.json` states clearly that the service is static-only and not a durable indexer/read-model, and now records both `health_url` and `local_health_url` alongside `rpc_base_url`, so operators can preserve the reverse-proxy-facing endpoint and the local bind probe in the same evidence packet. It now exposes the current Day-1 read-only contract:

- `query-task/<task_id>`
- `query-events/<task_id>?limit=<n>`
- `query-capability-audit/<subject-or-token>`
- `query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>`

Fail-closed boundary for operator handoff: this placeholder contract does **not** currently imply public Day-1 support for `block`, `tx`, or `account` queries. Until the durable indexer / historical read-model track closes, keep those surfaces out of scaffold-generated handoff language instead of inferring them from future explorer aspirations or upstream RPC internals.

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
- `deployment_evidence_scope=placeholder-only`
- `rank1_read_surface_blocker=still-open`
- `durable_indexer_status=not-implemented-in-this-scaffold`
- `durable_read_anchor_complete=false`
- `durable_read_anchors.ingestion_source=missing-placeholder-scaffold`
- `durable_read_anchors.checkpoint_store=missing-placeholder-scaffold`
- `durable_read_anchors.replay_start_anchor=missing-placeholder-scaffold`
- `durable_read_anchors.retention_scope=rpc-window-bounded`
- `durable_read_anchors.archive_owner=missing-placeholder-scaffold`
- `durable_read_anchors.lag_slo=missing-placeholder-scaffold`
- a note that historical queries remain bounded by current RPC retention until a durable indexer/archive strategy exists
- a note that durable read anchors remain intentionally unset until a real indexer/read-model exists

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
It also re-emits the same operator-facing contract fields as the up/status scripts, including the Day-1 read-contract markers, so handoff/debug notes can still quote the canonical paths and read-only boundary even when the service is already stopped. If the current env file is malformed, the stop helper still tears down any live PID first and then emits `config_warning=...`, so operators do not get stuck with a running placeholder just because the handoff/env contract drifted into an invalid state. The shutdown path now also emits the terminal state markers that automation can key on without having to call `status` again:

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
- `deployment_evidence_scope=placeholder-only`
- `rank1_read_surface_blocker=still-open`
- `durable_indexer_status=not-implemented-in-this-scaffold`
- `durable_read_anchor_complete=false`
- `durable_read_anchor_missing_count=6`
- `durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo`
- `durable_read_anchor_ingestion_source=missing-placeholder-scaffold`
- `durable_read_anchor_checkpoint_store=missing-placeholder-scaffold`
- `durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold`
- `durable_read_anchor_retention_scope=rpc-window-bounded`
- `durable_read_anchor_archive_owner=missing-placeholder-scaffold`
- `durable_read_anchor_lag_slo=missing-placeholder-scaffold`

Likewise, `explorer_service_up.sh` now emits the same `service_mode` / `production_ready` markers plus `public_base_url=...`, `rpc_base_url=...`, and `local_health_url=...` on success, "already running", and fail-fast exits, so operator notes can quote one consistent contract without having to run `status` first. It now also emits `deployment_evidence_scope=placeholder-only`, `rank1_read_surface_blocker=still-open`, `durable_indexer_status=not-implemented-in-this-scaffold`, `durable_read_anchor_complete=false`, `durable_read_anchor_missing_count=6`, `durable_read_anchor_missing_fields=...`, and the flat `durable_read_anchor_*=` placeholders so bring-up notes preserve the same fail-closed blocker language as `status`/`down`. Its startup gate intentionally probes the local bind target rather than `EXPLORER_PUBLIC_BASE_URL`, so a reverse-proxy-facing public URL can still differ from the local loopback/host bind without breaking the operator bring-up check.

## Operator caution

Do **not** use this scaffold as evidence that TRNM has closed the public-mainnet explorer/indexer blocker.
It only proves that:

- one minimal service boundary is documented,
- one local operator flow exists,
- one health/log/PID contract is visible.

The remaining blocker still requires durable indexing, replay semantics, historical query policy, and a real deployment/SLO story.

Treat `durability_boundary=ephemeral-rpc-window-only` as a fail-closed reminder that this scaffold has no persisted cursor/checkpoint/read-model state of its own: once the upstream RPC retention window no longer carries a record, the scaffold has no independent durability claim to fall back on.
