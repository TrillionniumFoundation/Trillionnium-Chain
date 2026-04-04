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

## Preferred capture flow

优先不要手工拼接 placeholder handoff note。
当前最稳妥的路径是先运行：

```bash
./trillionnium-rust/scripts/v2/capture_explorer_scaffold_handoff.sh
```

然后把同一输出目录里的以下三份 artifact 作为单一 evidence packet 使用：

- `summary.txt`
- `status.txt`
- `index.json`

最小原则：

- `summary.txt` 作为 operator-facing 汇总入口，优先承载 `template_path=`、`durable_template_path=`、`template_selection=placeholder-scaffold-only`、`durable_template_allowed=false`、`durable_template_rejection_reason=`、`deployment_template_boundary=`、`truth_source_*=`、`replay_command=`、`status_command=`、`rollback_command=` 与 placeholder fail-closed markers
- `status.txt` 保留 live runtime / probe / bind-path 证据，避免只剩 public URL 而丢失本地 deployment boundary
- `index.json` 保留实际对外静态读面声明，避免 handoff note 只引用 CLI/status 侧而没有 served payload 对照

如果不是从同一个 capture 目录抽取这三份 artifact，就把 note 视为 **evidence bundle incomplete**，而不是默认当作有效 placeholder handoff。

## Fail-closed boundary

如果下列任一条不成立，就不要把本模板生成的 handoff note 写成 Rank 1 blocker 已关闭：

- `deployment_evidence_scope=placeholder-only` 没被原样保留
- `deployment_evidence_scope` 仅出现在说明文字里、却没有作为 packet 字段被逐字保留
- `service_mode=operator-facing-static-scaffold` 没被原样保留
- `rank1_read_surface_blocker=still-open` 没被原样保留
- `durable_indexer_status=not-implemented-in-this-scaffold` 没被原样保留
- `durable_read_anchor_complete=false` 没被原样保留
- `durable_read_anchor_missing_count=6` 或 `durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo` 没被原样保留
- 6 个 durable-read anchors 缺失时，却被误写成已补齐
- note 中把 `block` / `tx` / `account` / archive / historical read-model 写成 Day-1 已承诺 surface

默认解释：

> **本模板只能证明 placeholder deployment path 是可复述的，不能证明 durable read path 已关闭。**

额外 fail-closed 规则：

> **如果证据起点仍是 `capture_explorer_scaffold_handoff.sh` / `explorer_service_status.sh` / scaffold-only ticket 文本产物，就不允许仅靠手工补字段把 note 升格成 durable read service handoff。**
> **一旦要宣称 non-placeholder durable boundary，必须改用独立的 durable-service packet，并同时具备真实 non-placeholder deployment、6 个 durable-read anchors、以及 replay / restore / lag evidence。**

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
read_contract_source=rpc-read-surface
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
# note: `historical_query_scope=rpc-retention-bounded` is the current placeholder query boundary,
# while `durable_read_anchor_retention_scope=rpc-window-bounded` is only the placeholder value for the
# future durable-read anchor named `retention_scope`; do not collapse them into a generic “history supported” claim.
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
index_json_durable_read_anchor_missing_count=6
index_json_durable_read_anchor_missing_fields=ingestion_source,checkpoint_store,replay_start_anchor,retention_scope,archive_owner,lag_slo
index_json_durable_read_anchor_ingestion_source=missing-placeholder-scaffold
index_json_durable_read_anchor_checkpoint_store=missing-placeholder-scaffold
index_json_durable_read_anchor_replay_start_anchor=missing-placeholder-scaffold
index_json_durable_read_anchor_retention_scope=rpc-window-bounded
index_json_durable_read_anchor_archive_owner=missing-placeholder-scaffold
index_json_durable_read_anchor_lag_slo=missing-placeholder-scaffold
index_json_durable_read_anchors.ingestion_source=missing-placeholder-scaffold
index_json_durable_read_anchors.checkpoint_store=missing-placeholder-scaffold
index_json_durable_read_anchors.replay_start_anchor=missing-placeholder-scaffold
index_json_durable_read_anchors.retention_scope=rpc-window-bounded
index_json_durable_read_anchors.archive_owner=missing-placeholder-scaffold
index_json_durable_read_anchors.lag_slo=missing-placeholder-scaffold
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

1. 若 `capture_explorer_scaffold_handoff.sh` 可用，优先直接引用同一 output dir 下的 `summary.txt` / `status.txt` / `index.json`，不要手工从多次运行结果里混拷字段。
2. `EXPLORER_*` runtime knobs must be copied as exact values, not paraphrased.
3. The status block must be copied from script output verbatim for the fail-closed markers.
4. Preserve `bind_host`, `bind_port`, `public_base_url`, and `env_file` so the handoff records the actual local deployment boundary rather than only the reverse-proxy-facing URL.
5. `/index.json` proof may come from `curl`, browser fetch, or direct file read, but the note must preserve where it was fetched from.
6. Copy the status-side read-contract markers verbatim too: `read_contract_mode`, `read_contract_source`, `day1_surface`, `query_events_default_limit`, `query_events_max_limit`, and `write_paths_exposed`. Do not rely on `service_mode` alone, because the handoff note should freeze the actual Day-1 read surface rather than just the deployment shape.
7. Preserve the matching `/index.json` contract markers (`index_json_read_contract_mode`, `index_json_read_contract_source`, `index_json_day1_surface`, limit fields, and durability markers) so operators can prove the served static payload matches the CLI/status contract instead of only asserting `index_json_declares_day1_contract=true`.
8. If reverse proxy and local bind differ, preserve both `health_url` and `local_health_url`, plus the corresponding `health_probe_url` / `local_health_probe_url` fields.
9. Preserve both `replay_command` and `rollback_command` so the same placeholder bring-up path can be re-run or torn down without reconstructing it from memory.
10. When `summary.txt` is available, also preserve `template_path=`, `durable_template_path=`, `template_selection=`, `durable_template_allowed=`, `durable_template_rejection_reason=`, `deployment_template_boundary=`, and the `truth_source_*=` lines verbatim; they are the mechanical hint for which template the next operator is allowed to use.
11. If `truth_source_go_no_go_panel=` is emitted as `missing-in-this-snapshot:...`, keep that exact value. It means the current repo snapshot does not carry that truth source locally; do not hand-edit the packet into claiming a GO/NO-GO panel file that the snapshot cannot actually prove.
12. Preserve `durable_read_anchor_missing_count` together with `durable_read_anchor_missing_fields`; do not keep one while trimming the other, because the pair is the fail-closed proof that the scaffold still lacks all 6 durable-read anchors.
13. If any durable-read anchor is later filled with a real value, stop using this placeholder-only template and move to a durable-service handoff packet instead.

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
- one emitted status block with fail-closed markers intact, including `read_contract_mode`, `read_contract_source`, `day1_surface`, `query_events_default_limit`, `query_events_max_limit`, `write_paths_exposed`, and `durable_read_anchor_missing_count` + `durable_read_anchor_missing_fields`
- explicit local deployment-path fields (`bind_host`, `bind_port`, `public_base_url`, `env_file`)
- explicit probe evidence (`health_probe_url`, `local_health_probe_url`)
- one `/index.json` fetch proof that also preserves the served read-contract/durability markers, including `index_json_read_contract_source`, not just a boolean declaration
- one explicit blocker note stating placeholder-only scope
- one replay command
- one rollback command

If any item above is missing, treat the note as incomplete operator evidence rather than a valid scaffold handoff packet.
