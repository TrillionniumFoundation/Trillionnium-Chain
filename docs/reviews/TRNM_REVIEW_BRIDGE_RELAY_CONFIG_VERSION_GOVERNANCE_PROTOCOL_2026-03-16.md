# TRNM Bridge Relay — 配置版本治理接线协议复核（2026-03-16）

> 目标：把 `bridge-relay` 的 `config_version` 从“链下测试约束」升级为可用于上线接线的最小治理协议。

## 变更摘要（已落地）

在 `contracts/bridge-relay` 已完成：

- `BridgeSettlementMessage` 新增 `config_version: u64`
- `submit_proof` 强制校验 `message.config_version == self.config_version`
- `set_admin` / `set_min_validator_signatures` / `set_validators` 每次变更后 `config_version += 1`
- 新增 `ConfigVersionUpdated` 审计事件并纳入 `normalized_audit_log`
- 新增并发版治理入口：
  - `config_version()`
  - `set_admin_with_version`
  - `set_min_validator_signatures_with_version`
  - `set_validators_with_version`
- 测试覆盖：
  - `submit_proof_rejects_wrong_config_version`
  - `config_version_gating_rejects_stale_expected_version`
  - `config_version_gating_accepts_matching_version`

## 可执行治理接线规范（建议接入点）

### 1) 状态快照
- 外部治理服务在提交任何治理变更前，先读取 `config_version()`。
- 作为后续调用中的 `expected_config_version`。

### 2) 变更请求约束
- 所有治理变更必须走 `*_with_version` 接口。
- 如果返回 `InvalidConfigVersion { expected, got }`：
  1. 说明存在并发更新，
  2. 重新拉取 `expected = config_version()`，
  3. 用最新版本与最新参数重试。

### 3) 提交证明方要求
- 构造证明时必须携带当前 `config_version`。
- 任何过期版本的 proof 不能被提交（`InvalidConfigVersion`）。

### 4) 错误语义
- `InvalidConfigVersion` 是治理层和证明层的**fail-closed**闸门。
- 必须在客户端将其视作“可重试类（先拉取版本）”而非“业务可忽略错误”。

## 风险与边界（本轮仍未闭环）

- 本版本未引入真实链上治理源（proposal/epoch/root-of-trust）
- `admin`/`validator` 仍为本地状态机持久形式；适合先演进到“源于治理动作的输入映射”
- `proof` 仍未绑定到源链最终性证据（receipt/finality）

## 对接建议（最小实现路径）

1. 在治理服务层保留 `expected_config_version`（ETag/乐观锁）
2. 所有变更接口改为 `*_with_version`
3. proof 生产链路在打包时读取当前版本并签名后提交
4. 在运维/runbook 中记录变更链路（谁、何时、旧版本-新版本、变更结果）