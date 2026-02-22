# Trillionnium Rust L1 共识机制漏洞清单与攻防测试矩阵（2026-02-22）

目标：把“感觉安全”变成“可重复验证的安全结论”。

## P0 高危面（先打）

1. **重放/nonce 绕过**
   - 风险：重复提交、乱序 nonce 导致双执行或状态污染。
   - 现有防线：replay 拒绝、nonce 单调约束、稳定错误码。
   - 验证脚本：
     - `trillionnium-rust/scripts/run_request_fault_injection.sh`
     - `trillionnium-rust/scripts/check_request_tx_binding.sh`

2. **状态机非法迁移**
   - 风险：跳过关键状态直接落终态，导致结算或惩罚错误。
   - 现有防线：`RequestStatus` 单一源 + 迁移守卫 + 全矩阵测试。
   - 验证命令：
     - `cargo test -p trnm-types -p trnm-worker-agent -p trnm-rpc`

3. **共识故障恢复（分区/重启/round-change）**
   - 风险：长分叉、不可恢复停滞、最终性异常。
   - 现有防线：fault matrix + restart/recovery gate。
   - 验证脚本：
     - `trillionnium-rust/scripts/run_consensus_fault_matrix.sh`
     - `trillionnium-rust/scripts/check_bft_restart_recovery.sh`
     - `trillionnium-rust/scripts/check_bft_round_change.sh`

## P1 中危面（次优先）

4. **Adapter 资源耗尽/DoS**
   - 风险：超时+重试放大导致节点资源耗尽。
   - 防线：timeout/retry budget，默认参数回退。
   - 验证：
     - `cargo test -p trnm-worker-agent`
     - 本地证据包：`trillionnium-rust/scripts/run_local_release_evidence.sh`

5. **事件/回执一致性漂移**
   - 风险：链上状态与事件不一致，审计失真。
   - 验证：
     - `trillionnium-rust/scripts/check_event_fields.sh`
     - `trillionnium-rust/scripts/check_event_replay_smoke.sh`

## 通过标准（工业级前最低门槛）

- P0 项全通过，且无“偶现红灯”。
- 同一代码版本连续完成 >=3 轮安全矩阵（本地或 CI）全绿。
- 每轮必须产出 evidence 目录（summary + 分项日志 + 时间戳）。

## 执行建议（今日）

1) 跑一轮 `run_consensus_security_matrix.sh`（见新增脚本）
2) 修复失败项（仅一类一类清）
3) 再跑第二轮确认非偶发
4) 生成对外安全进度摘要（仅报事实，不夸大）
