# P2 PR Notes — Retire Legacy `SubmitResult` by Default

更新日期：2026-02-19
范围：PoUW workload 模块（参数默认值、keeper 测试、发布验收口径）

## 1) 变更动机

PoUW 主流程已迁移到 `commit_result + reveal_result`。继续默认开放 legacy `SubmitResult` 会带来：
- 协议路径分叉（双路径维护成本）
- 状态机验证与审计复杂度上升
- 发布验收口径不清晰（默认行为与目标行为不一致）

本次目标：将 legacy 路径从“默认可用”收敛为“默认关闭，仅兼容测试显式开启”。

## 2) 核心变更

### A. 默认参数切换
- 文件：`chain/x/workload/types/params.go`
- 变更：
  - `DefaultParams().AllowLegacySubmitResult`：`true -> false`

### B. 行为守卫测试
- 文件：`chain/x/workload/keeper/msg_server_pouw_test.go`
- 新增：
  - `TestSubmitResultLegacyDisabledByDefault`
- 断言：默认参数下调用 legacy `SubmitResult` 返回错误，且包含
  - `legacy submit_result is disabled`

### C. 兼容测试显式开启 legacy（避免隐式依赖默认值）
- 文件：
  - `chain/x/workload/keeper/challenge_id_zero_regression_test.go`
  - `chain/x/workload/keeper/dispute_resolver_injection_test.go`
  - `chain/x/workload/keeper/fund_flow_event_test.go`
  - `chain/x/workload/keeper/msg_server_pouw_test.go`
  - `chain/x/workload/keeper/pouw_economics_test.go`
- 处理方式：测试内显式 `SetParams(...AllowLegacySubmitResult=true)`

### D. 文档口径同步
- 文件：
  - `docs/protocol/upgrade-migration-v1.md`
  - `docs/protocol/pouw-v0.2-release-checklist.md`
- 调整点：
  - 将 `allow_legacy_submit_result` 基线更新为 `false`
  - release checklist 明确“默认关闭 + 兼容测试显式开启”

## 3) 风险评估

### 主要风险
1. 旧客户端仍调用 legacy `SubmitResult` 导致交易失败
2. 外部脚本/运维 runbook 若未更新，可能出现验收误报

### 缓解措施
1. 保留参数开关（非硬删接口），兼容测试可显式开启
2. 在迁移文档和 release checklist 中明确新口径
3. 新增默认关闭行为测试，防止后续回归

## 4) 回滚点

若线上发现兼容性问题，可通过参数治理临时回切：
- `allow_legacy_submit_result=false -> true`

回滚范围：仅参数层；不涉及状态迁移回滚与存储结构回滚。

## 5) 验证证据

在 `chain/` 目录执行：
- `go test ./x/workload/...` ✅
- `go test ./...` ✅

建议在 CI 追加：
- 1 条默认参数路径（legacy 拒绝）
- 1 条显式兼容路径（legacy 开启）

## 6) 审阅要点（Reviewer Checklist）

- [ ] 默认参数切换是否仅影响预期路径
- [ ] 旧测试是否已消除“隐式依赖默认值”
- [ ] 文档口径是否与代码一致
- [ ] 回滚策略是否可操作（参数治理可回切）