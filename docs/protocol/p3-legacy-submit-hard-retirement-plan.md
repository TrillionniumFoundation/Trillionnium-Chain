# P3 Plan: Legacy `SubmitResult` Hard Retirement

更新日期：2026-02-19  
状态：Draft（proposed）

## 1. 目标

将 legacy `SubmitResult` 从“默认关闭但可启用”推进到“代码层彻底退役（删除兼容路径）”。

## 2. 前置条件（Go 条件）

满足以下条件后，允许进入删除实现阶段：

1. **观测窗口内 legacy 调用为 0**
   - 连续观察至少 1~2 个迭代周期
   - 观测范围：测试网 + 预生产环境

2. **运维脚本无 legacy 依赖**
   - 仓库内脚本、runbook、验收文档不再要求 legacy path

3. **客户端/worker 升级完成**
   - 官方 worker/SDK 默认仅走 commit+reveal
   - 对外发布过升级公告并给出迁移窗口

4. **回滚预案可执行**
   - 明确删除后若遇兼容事件的应急策略（版本回退/热修）

## 3. 分阶段执行

### 阶段 A：观测与证据（当前阶段）
- 在 legacy 入口增加计数/事件（若已存在则标准化字段）
- 每日/每周输出统计：legacy 调用次数、调用来源、失败原因

交付物：
- `docs/protocol/legacy-submit-observability.md`（建议新增）
- 统计快照归档到 `data/observability/`

### 阶段 B：软封禁强化
- 保持默认关闭
- 将兼容开关启用行为标记为“临时应急用途”，并在文档标红
- 在 checklist 中加入“启用兼容开关需要审批/记录”

交付物：
- `docs/protocol/pouw-v0.2-release-checklist.md`（增补审批项）

### 阶段 C：硬退役（删除代码）
- 删除 `MsgSubmitResult` handler 的业务分支
- 清理参数：`allow_legacy_submit_result`
- 删除/迁移 legacy 相关测试
- 更新 proto/API 文档与 CLI 帮助

交付物：
- 代码 PR（breaking-change 标记）
- 升级迁移文档 v2

## 4. 影响面清单（待逐项确认）

- `chain/x/workload/keeper/msg_server_pouw.go`（legacy 入口）
- `chain/x/workload/types/params.go`（legacy 参数定义）
- `chain/proto/chain/workload/params.proto`（legacy 参数字段）
- `chain/x/workload/types/tx.pb.go` / CLI 自动生成入口（兼容层）
- 文档与 checklist（升级/发布/治理模板）

## 5. 风险与缓解

### 风险
- 仍有外部调用者使用 legacy 提交，删除后交易直接失败。

### 缓解
- 先做观测，数据驱动删除。
- 删除前至少一次公告窗口。
- 保留可快速发布热修版本能力。

## 6. 时间表（建议）

- T+0（本周）：完成观测方案与字段标准化
- T+7：产出第一周调用统计，确认是否仍有 legacy 流量
- T+14：若持续为 0，提交硬退役 PR
- T+21：完成主网/测试网验证并关闭 P3

## 7. 验收标准（DoD）

- [ ] 观测窗口内 legacy 调用持续为 0
- [ ] 所有官方脚本与文档无 legacy 依赖
- [ ] 删除后 `go test ./...` 通过
- [ ] P0/P1 gate 全通过
- [ ] 升级迁移文档与发布记录完整