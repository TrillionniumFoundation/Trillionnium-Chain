# TRNM Explorer Scaffold Handoff Template (2026-04-04)

适用范围：`trillionnium-rust/docs/runbooks/explorer-service-scaffold.md` 所描述的 **operator-facing static scaffold / placeholder-only** 部署形态。

## 文档目的

这不是 durable indexer / historical read-model / production explorer backend 的 handoff packet。

它只回答一个更窄的问题：

> **当 operator 使用当前 explorer scaffold 做 bring-up、rehearsal、或 ticket handoff 时，最小、可复制、不会夸大 blocker closure 的交接模板应该长什么样。**

引用本模板时，必须同时参考：

- `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`
- `trillionnium-rust/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`

## Fail-closed boundary

如果下列任一条不成立，就不要把本模板生成的 handoff note 写成 Rank 1 blocker 已关闭：

- `deployment_evidence_scope=placeholder-only` 没被原样保留
- `rank1_read_surface_blocker=still-open` 没被原样保留
- `durable_indexer_status=not-implemented-in-this-scaffold` 没被原样保留
- `durable_read_anchor_complete=false` 没被原样保留
- `durable_read_anchor_missing_count=6` 或 `durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo` 没被原样保留
- 6 个 durable-read anchors 缺失时，却被误写成已补齐
- note 中把 `block` / `tx` / `account` / archive / historical read-model 写成 Day-1 已承诺 surface

默认解释：

> **本模板只能证明 placeholder deployment path 是可复述的，不能证明 durable read path 已关闭。**

## Copy/paste handoff template

```text
TRNM_EXPLORER_SCAFFOLD_HANDOFF
scope=placeholder-only
handoff_date=<YYYY-MM-DD>
operator=<name-or-team>
repo_snapshot=<git-sha>
runbook=trillionnium-rust/docs/runbooks/explorer-service-scaffold.md
truth_source_day1_contract=trillionnium-rust/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md

# runtime knobs (copy exact values)
EXPLORER_HOST=<value>
EXPLORER_PORT=<value>
EXPLORER_PUBLIC_BASE_URL=<value>
EXPLORER_HEALTH_URL=<value>
EXPLORER_RPC_BASE_URL=<value>

# status block (copy emitted values verbatim)
state=<running|down|stale-pid|invalid-config|...>
service_mode=operator-facing-static-scaffold
production_ready=false
bind_host=<value>
bind_port=<value>
public_base_url=<value>
health_url=<value>
local_health_url=<value>
index_url=<value>
rpc_base_url=<value>
pid_file=<value>
log_file=<value>
env_file=<value>
public_dir=<value>
health_file=<value>
index_file=<value>
read_contract_mode=read-only
day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>
query_events_default_limit=100
query_events_max_limit=500
write_paths_exposed=false
deployment_evidence_scope=placeholder-only
rank1_read_surface_blocker=still-open
durable_indexer_status=not-implemented-in-this-scaffold
historical_query_scope=rpc-retention-bounded
durability_boundary=ephemeral-rpc-window-only
archive_strategy=not-configured-static-scaffold
read_replica_strategy=not-configured-static-scaffold
durable_read_anchor_complete=false
durable_read_anchor_missing_count=6
durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo
durable_read_anchor_ingestion_source=missing-placeholder-scaffold
durable_read_anchor_checkpoint_store=missing-placeholder-scaffold
durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold
durable_read_anchor_retention_scope=rpc-window-bounded
durable_read_anchor_archive_owner=missing-placeholder-scaffold
durable_read_anchor_lag_slo=missing-placeholder-scaffold
health=<ok|down|unknown>
health_probe=<active|disabled-curl-unavailable|not-run-state-down|not-run-state-not-running|invalid-config>
health_probe_url=<value>
local_health=<ok|down|unknown>
local_health_probe=<active|disabled-curl-unavailable|not-run-state-down|not-run-state-not-running|invalid-config>
local_health_probe_url=<value>

# /index.json proof
index_json_fetched_at=<timestamp>
index_json_path_or_url=<value>
index_json_declares_day1_contract=true
index_json_declares_placeholder_only=true
index_json_service_mode=operator-facing-static-scaffold
index_json_production_ready=false
index_json_rpc_base_url=<value>
index_json_health_url=<value>
index_json_local_health_url=<value>
index_json_read_contract_mode=read-only
index_json_read_contract_source=rpc-read-surface
index_json_day1_surface=query-task/<task_id>,query-events/<task_id>?limit=<n>,query-capability-audit/<subject-or-token>,query-normalized-audit-events?source=<source>&eventType=<type>&limit=<n>&cursor=<cursor>
index_json_query_events_default_limit=100
index_json_query_events_max_limit=500
index_json_write_paths_exposed=false
index_json_historical_query_scope=rpc-retention-bounded
index_json_durability_boundary=ephemeral-rpc-window-only
index_json_archive_strategy=not-configured-static-scaffold
index_json_read_replica_strategy=not-configured-static-scaffold
index_json_durable_read_anchor_complete=false
index_json_notes_include=static-scaffold-only,not-a-durable-indexer,not-a-production-read-model

# explicit blocker note (must stay explicit)
blocker_note=this_evidence_does_not_close_durable_indexer_historical_read_model_or_production_explorer_backend

# optional local commands used
replay_command=./trillionnium-rust/scripts/v2/explorer_service_up.sh
status_command=./trillionnium-rust/scripts/v2/explorer_service_status.sh
index_fetch_command=<curl-or-cat-command>
rollback_command=./trillionnium-rust/scripts/v2/explorer_service_down.sh
```

## Operator instructions

1. `EXPLORER_*` runtime knobs must be copied as exact values, not paraphrased.
2. The status block must be copied from script output verbatim for the fail-closed markers.
3. Preserve `bind_host`, `bind_port`, `public_base_url`, and `env_file` so the handoff records the actual local deployment boundary rather than only the reverse-proxy-facing URL.
4. `/index.json` proof may come from `curl`, browser fetch, or direct file read, but the note must preserve where it was fetched from.
5. Copy the status-side read-contract markers verbatim too: `read_contract_mode`, `day1_surface`, `query_events_default_limit`, `query_events_max_limit`, and `write_paths_exposed`. Do not rely on `service_mode` alone, because the handoff note should freeze the actual Day-1 read surface rather than just the deployment shape.
6. Preserve the matching `/index.json` contract markers (`index_json_read_contract_mode`, `index_json_day1_surface`, limit fields, and durability markers) so operators can prove the served static payload matches the CLI/status contract instead of only asserting `index_json_declares_day1_contract=true`.
7. If reverse proxy and local bind differ, preserve both `health_url` and `local_health_url`, plus the corresponding `health_probe_url` / `local_health_probe_url` fields.
8. Preserve both `replay_command` and `rollback_command` so the same placeholder bring-up path can be re-run or torn down without reconstructing it from memory.
9. Preserve `durable_read_anchor_missing_count` together with `durable_read_anchor_missing_fields`; do not keep one while trimming the other, because the pair is the fail-closed proof that the scaffold still lacks all 6 durable-read anchors.
10. If any durable-read anchor is later filled with a real value, stop using this placeholder-only template and move to a durable-service handoff packet instead.

## What this template intentionally does not claim

This template does **not** claim any of the following are closed:

- durable indexer pipeline
- historical read-model
- archive/read-replica strategy
- public `block` / `tx` / `account` Day-1 read support
- non-placeholder explorer backend/API
- read-lag SLO ownership

## Minimal definition of done for using this template

A scaffold handoff note is acceptable only if it includes all of the following:

- exact `EXPLORER_*` runtime values
- one emitted status block with fail-closed markers intact, including `read_contract_mode`, `day1_surface`, `query_events_default_limit`, `query_events_max_limit`, `write_paths_exposed`, and `durable_read_anchor_missing_count` + `durable_read_anchor_missing_fields`
- explicit local deployment-path fields (`bind_host`, `bind_port`, `public_base_url`, `env_file`)
- explicit probe evidence (`health_probe_url`, `local_health_probe_url`)
- one `/index.json` fetch proof that also preserves the served read-contract/durability markers, not just a boolean declaration
- one explicit blocker note stating placeholder-only scope
- one replay command
- one rollback command

If any item above is missing, treat the note as incomplete operator evidence rather than a valid scaffold handoff packet.
