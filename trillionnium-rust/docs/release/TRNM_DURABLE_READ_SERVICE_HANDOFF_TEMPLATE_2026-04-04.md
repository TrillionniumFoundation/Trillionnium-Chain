# TRNM Durable Read Service Handoff Template (2026-04-04)

适用范围：未来 **non-placeholder durable read service / explorer backend / indexer-backed deployment**。

## 文档目的

这份模板是给未来 **已脱离 placeholder scaffold** 的 read service 使用的 handoff packet 骨架。

它只回答一个问题：

> **当 TRNM 具备 durable indexer / historical read-model / non-placeholder explorer backend 后，operator handoff note 至少应该冻结哪些证据，才能不把 Rank 1 blocker 的关闭写成口头承诺。**

当前状态必须明确：

- 本模板是 **future-state truth-source skeleton**；
- 它**不是**当前仓库已存在 durable read service 的证明；
- 在 `ingestion_source` / `checkpoint_store` / `replay_start_anchor` / `retention_scope` / `archive_owner` / `lag_slo` 仍未被真实实现并落地前，**不得**用本模板生成“Rank 1 已关闭”的 handoff note。

引用本模板时，必须同时参考：

- `trillionnium-rust/docs/release/TRNM_RANK1_READ_SURFACE_TASK_BOARD_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `trillionnium-rust/docs/release/TRNM_PUBLIC_MAINNET_GO_NO_GO_PANEL_2026-04-04.md`
- `trillionnium-rust/docs/runbooks/explorer-service-scaffold.md`
- `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`

## Template selection rule

在 operator handoff 场景里，先决定**你处于 placeholder scaffold，还是 non-placeholder durable read service**，再选模板。

使用本模板之前，至少先逐项回答：

- 当前部署是否仍然引用 `explorer-service-scaffold.md` 的静态 scaffold bring-up 路径？
- `service_mode` 是否已经能真实写成 `non-placeholder-durable-read-service`？
- 6 个 durable-read anchors 是否都有真实值，而不是 `missing-*` / `placeholder-*` / `not-configured-*`？
- 是否真的存在独立的 replay / restore / checkpoint / lag evidence？

只要上面任一项答案是否定的，就**不要**使用本模板；改用：

- `trillionnium-rust/docs/release/TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md`

一旦进入 durable handoff，note 里还应显式冻结：

- `deployment_evidence_scope=durable-read-service`

这样才能与 placeholder packet 中的 `deployment_evidence_scope=placeholder-only` 形成机械可判定的边界，而不是仅靠口头描述“看起来像 durable”。

Fail-closed choice:

> **缺 anchor、缺 replay/restore 证据、仍靠 scaffold bring-up、或 `service_mode` 还不是 non-placeholder durable read service 时，一律按 placeholder-only handoff 处理。**

### Template selection quick matrix

在 release review / operator handoff / incident follow-up 里，先把当前证据放进下面这张矩阵，再决定能不能用 durable 模板：

| 当前证据形态 | 允许使用的模板 | 结论 |
| --- | --- | --- |
| 仍使用 `explorer_service_up.sh` / `explorer_service_status.sh` 的静态 scaffold bring-up，且证据以 `deployment_evidence_scope=placeholder-only` 为主 | `TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | 只能说明 placeholder deployment path 已被记录；**不能**说明 Rank 1 已关闭 |
| `service_mode` 不是 `non-placeholder-durable-read-service` | `TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | 仍按 placeholder-only 处理 |
| 6 个 durable-read anchors 任一缺失、为空、或仍是 `missing-*` / `placeholder-*` / `not-configured-*` | `TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | durable read boundary 仍未成立 |
| replay / restore / lag / checkpoint 证据缺任一项 | `TRNM_EXPLORER_SCAFFOLD_HANDOFF_TEMPLATE_2026-04-04.md` | 仍不得写成 durable handoff |
| 只有 non-placeholder deployment boundary、6 个 durable-read anchors、replay/restore 命令、lag/health evidence 同时具备 | **本模板** | 才能进入 durable read service handoff 审阅 |

机械判定规则：

- 先看 `deployment_evidence_scope=` 与 `service_mode=`；二者任一仍指向 placeholder，或 `deployment_evidence_scope` 根本未被显式写出，就停止，不再往 durable 模板补写。
- 再逐项核对 6 个 durable-read anchors；**不是“将来会填”而是“当前 note 已有真实值”**。
- 最后核对 replay / restore / checkpoint / lag evidence；缺任何一项，都回退到 placeholder-only 口径。

## Fail-closed boundary

如果下列任一条不成立，就不要把 durable read service handoff note 写成 Rank 1 blocker 已关闭：

- `deployment_evidence_scope=durable-read-service` 没被原样保留
- `service_mode=non-placeholder-durable-read-service` 没被原样保留
- `production_ready=true` 没被真实部署证据支持
- 6 个 durable-read anchors 中任意一项缺失或仍是 placeholder 值
- 没有明确的 deploy / replay / restore 命令
- 没有明确的 lag / freshness / health 证据
- 没有明确说明 historical read-model 的 retention / archive ownership
- note 仍把当前 scaffold 证据与 durable service 证据混在一起，无法区分 placeholder-only 与 non-placeholder deployment

默认解释：

> **只有当 durable-read anchors、部署路径、重放恢复路径、以及 lag/health 证据一起出现时，handoff note 才有资格讨论 Rank 1 closure；否则仍按 blocker-open 处理。**

## Copy/paste durable-service handoff template

```text
TRNM_DURABLE_READ_SERVICE_HANDOFF
scope=durable-read-service
handoff_date=<YYYY-MM-DD>
operator=<name-or-team>
repo_snapshot=<git-sha>
deployment_evidence_scope=durable-read-service
service_name=<value>
service_mode=non-placeholder-durable-read-service
production_ready=<true|false>

# deployment boundary
service_binary_or_entrypoint=<value>
deploy_mode=<systemd|container|k8s|other>
deploy_host_or_cluster=<value>
public_base_url=<value>
health_url=<value>
version_url=<value-or-na>
config_source=<value>
log_path=<value>
metrics_endpoint=<value-or-na>

# durable-read anchors (all required)
ingestion_source=<rpc-pull|event-stream|block-replay|mixed|other>
checkpoint_store=<sqlite|postgres|object-store|other>
replay_start_anchor=<genesis|checkpoint:<id>|block:<height>|other>
retention_scope=<bounded|durable-archive|tiered|other>
archive_owner=<name-or-team>
lag_slo=<value>

# historical read-model
historical_read_model_backend=<value>
historical_query_scope=<value>
replay_strategy=<value>
restore_strategy=<value>
duplicate_event_policy=<value>
reorg_or_replay_reconciliation=<value>

# runtime health / freshness evidence
health=<ok|degraded|down|unknown>
freshness_state=<current|lagging|stale|unknown>
current_lag=<value>
last_successful_checkpoint=<value>
last_replay_or_resync_at=<timestamp>
last_restore_drill_at=<timestamp-or-na>

# minimum public read contract evidence
read_contract_mode=read-only
served_day1_surface=<value>
write_paths_exposed=<true|false>
query_contract_truth_source=trillionnium-rust/docs/release/TRNM_DAY1_PUBLIC_READ_CONTRACT_2026-04-03.md

# commands preserved for operator replay
bringup_command=<value>
status_command=<value>
replay_command=<value>
restore_command=<value>
rollback_command=<value>

# explicit boundary note
blocker_note=this_packet_requires_real_durable_read_anchors_and_must_not_be_backfilled_from_placeholder_scaffold_evidence
```

## Operator instructions

1. `deployment_evidence_scope=durable-read-service` 必须显式出现；缺这一行时，按边界不清的无效 handoff note 处理。
2. 6 个 durable-read anchors 必须全部填写真实值；任一项缺失都按无效 handoff note 处理。
3. `production_ready=true` 只能在 deploy / replay / restore / lag evidence 同时具备时出现；否则写 `false`。
4. `lag_slo` 必须和实际 freshness/lag 证据一起出现，不能只写目标值不写当前观测值。
5. `historical_query_scope` 必须明确 bounded 与 durable 的边界，不得混写成模糊的“supports history”。
6. `archive_owner` 必须指向真实 owner/team，而不是占位词。
7. `restore_strategy` 不能省略；缺 restore 说明 durable read path 还不具备可信恢复闭环。
8. 如果 handoff note 里还引用 placeholder scaffold 输出，必须单独标注为旧证据/对照证据，不能替代 durable-service 字段。
9. `served_day1_surface` 应只写当前真实承诺的 Day-1 read surface，不能顺手把 future `block` / `tx` / `account` promise 提前写进来。

## What this template intentionally does not claim

这份模板本身**不**自动证明以下事项已经关闭：

- durable indexer pipeline 已实现
- historical read-model 已闭环
- archive / replay ownership 已落地
- lag SLO 已达标
- Rank 1 blocker 已关闭

它只是把 future durable service handoff 必须带哪些证据先冻结成 truth-source，避免未来 operator note 再次退化成口头描述。

## Minimal definition of done for using this template

一份 durable read service handoff note 只有在同时具备以下内容时才算有效：

- 一份显式标记 `deployment_evidence_scope=durable-read-service` 的 non-placeholder deployment boundary
- 6 个 durable-read anchors 的真实值
- 一份 explicit historical read-model / replay / restore 说明
- 一份 freshness / lag / checkpoint 证据
- 一组 bringup / status / replay / restore / rollback 命令
- 一条明确说明它不是从 placeholder scaffold 反向补写出来的 blocker note

如果任一项缺失，按 **durable-service handoff evidence incomplete** 处理，而不是 Rank 1 closed。
