# Trillionnium Web4 企业接入 Runbook（Track E3）

> 版本：v1（最小可用）
> 维护：LaneDAE

## 1. 目标与适用范围

本 runbook 用于企业首次接入 Trillionnium Web4 平台时的标准执行流程，覆盖：
- 身份与权限开通（DID + capability）
- 环境连通与最小验证
- 审计证据留存与回滚路径

## 2. 前置条件（Preflight）

1. 企业已完成组织主体登记并获得 `org_id`。
2. 安全联系人与运维联系人已确认。
3. 具备最小测试环境（非生产）与隔离凭据。
4. 已明确合规分级：`public` / `internal` / `restricted`。

## 3. 接入步骤（Step-by-step）

### Step 1：身份初始化
- 注册企业 DID（I1）并记录控制人。
- 生成首批 capability token（I2），按最小权限发放。

### Step 2：Agent 协议协商
- 选择协议：`mcp` 或 `a2a`（A1/A2）。
- 记录协议版本与适配器传输层（json-rpc / stdio / sse / streamable-http）。

### Step 3：最小链路验收
- 触发一条最小任务（非敏感数据）。
- 校验回执：任务状态、结算事件、provenance 字段齐备。

### Step 4：审计基线归档
- 导出本次接入审计包（E2）：请求、回执、策略快照、失败重试记录。
- 生成不可变指纹（hash）并登记在变更单。
- 附加策略回滚防护检查输出（E1），建议命令：`./scripts/v2/p11_policy_rollback_guard.sh`。

## 4. 验收标准（DoD）

- 首次接入端到端成功率 = 100%（最小样例窗口）。
- 关键审计字段完整：`request_id` / `task_id` / `provenance_fingerprint`。
- 回滚演练一次成功，且有可复盘证据。

## 5. 回滚方案

- 撤销新增 capability token。
- 冻结本次接入环境凭据。
- 标记接入状态为 `reverted` 并附根因标签。
- 根因标签建议使用稳定枚举（示例）：`schema_drift` / `auth_scope_mismatch` / `policy_conflict`。
- 根因标签格式约束：仅允许小写 snake_case（`[a-z0-9_]+`），禁止空格与大小写混用，避免审计聚合分桶漂移。
- 记录可复放的回滚命令模板（必须携带 `--root-cause-tag`、`--change-ticket-id` 与 `--operator-id`），示例：
  - `trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --operator-id <operator_id> --root-cause-tag <root_cause_tag>`
- 先执行一次 `--dry-run` 预演，确认参数与目标环境一致后再执行真实回滚：
  - `trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --operator-id <operator_id> --root-cause-tag <root_cause_tag> --dry-run`
- 单事件回滚建议追加 `--request-id <request_id>` 形成审计锚点（与 root_cause_tag 一起固化）。
  - `trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --root-cause-tag <root_cause_tag> --request-id <request_id>`
  - `trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --root-cause-tag <root_cause_tag> --request-id <request_id> --dry-run`
  - （如需显式执行人追踪）`trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --operator-id <operator_id> --root-cause-tag <root_cause_tag> --request-id <request_id>`
  - （如需显式执行人追踪）`trnm-onboard rollback --org-id <org_id> --env <env> --change-ticket-id <change_ticket_id> --operator-id <operator_id> --root-cause-tag <root_cause_tag> --request-id <request_id> --dry-run`
- 将最终执行命令与输出日志计算 `sha256` 并写入变更单，作为回滚可复盘锚点。

## 6. 证据清单（Evidence Checklist）

- [ ] 接入审批单（含 change_ticket_id）
- [ ] DID/capability 变更记录
- [ ] 协议版本与适配器传输层记录
- [ ] 隐私分级策略快照（privacy_tier）
- [ ] 最小任务 provenance_fingerprint 记录
- [ ] 最小任务执行与结算日志
- [ ] 审计包导出文件与 hash（SHA-256 小写 hex，64位）
- [ ] 回滚演练记录
- [ ] 回滚命令与输出日志的 sha256 记录
- [ ] 回滚执行人标识（operator_id）与变更单绑定记录
- [ ] 回滚根因标签（root_cause_tag）与审计事件 request_id 绑定记录
- [ ] NTP 时钟偏差检查记录（≤300秒）
- [ ] 审计事件时间戳格式校验记录（RFC3339 UTC，后缀 `Z`）
- [ ] 审计时间戳禁止小数秒（必须为整秒）
- [ ] 审计事件序列时间戳单调不倒退校验记录（按事件顺序）

> 时间戳格式示例（整秒、UTC）：`2026-03-07T01:55:00Z`（正则参考：`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`）
