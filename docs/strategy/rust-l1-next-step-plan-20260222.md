# Rust L1 精简执行计划（2026-02-22）

范围：基于当前仓库现状，不改代码；聚焦主线 **state machine / timeout / retry / gates**。

---

## 今日可完成（3项）

1. **跑通并归档一次 testnet preflight 证据包（硬门禁口径）**
   - 目标：用 `trillionnium-rust/scripts/testnet_preflight.sh` 生成当日可审计结果。
   - 验收：
     - preflight 末行出现 `[OK] testnet preflight passed`
     - 产物齐全：`run/preflight/*`、`run/audit/state-root-audit-*`、`run/bench/*`
   - 对应主线：`gates`（将口头状态转为证据状态）。

2. **完成 v1 状态机“迁移矩阵缺口清单”并冻结优先级（文档动作）**
   - 目标：基于现有 `create -> accept -> commit -> reveal -> challenge -> resolve` 与 event replay gate，补一页“已覆盖/待补覆盖”矩阵清单。
   - 验收：
     - 明确列出：已被 `run_v1_protocol_gates.sh` 覆盖的迁移；未覆盖的边界迁移（含 owner/截止时间）
   - 对应主线：`state machine`（防止冻结语义与测试覆盖脱节）。

3. **完成 timeout/retry 统一运行口径（runbook + 命令清单）**
   - 目标：把 worker 侧 `timeout + retry/backoff` 与 gate 执行口径整理为单页操作卡（仅文档，不改实现）。
   - 验收：
     - 明确默认参数来源（env/脚本）
     - 明确两条命令：`run_worker_receipt_gates.sh` 与 `run_worker_receipt_gates_real_cli.sh`
     - 明确失败分类（timeout / retry_exhausted / deterministic reject）
   - 对应主线：`timeout + retry + gates`（减少误判与口径漂移）。

---

## 本周必须收口（3项）

1. **Release Guard 放行条件闭环：nightly 连续 3 绿 + RC 证据齐套**
   - 完成标准：
     - `rust-l1-nightly-health` 连续 3 次 success（同主分支）
     - `release/rc-*/manifest.txt` 与 `nightly-streak.log` 等 evidence 完整
   - 价值：把“可发布”从主观判断变为可复核规则。

2. **Challenge Re-exec 从模板态收口到“可复跑流程态”**
   - 当前基础：已有模板与 smoke（`challenge_reexec_resolve_template*.sh`）。
   - 本周收口标准：
     - 输出一条固定演练路径（输入、执行、回写、验收）
     - 在 runbook 中明确异常分支与责任边界
   - 价值：补齐 `reveal/challenge/resolve` 之后的治理闭环。

3. **门禁矩阵冻结（哪些 hard gate、哪些 advisory）并对外统一口径**
   - 完成标准：
     - merge gate / nightly gate / worker strict gate / perf gate 的优先级与阻断级别一页说清
     - 与现有文档（`rust-l1-release-guard.md`、`MANUAL_MERGE_GATE_CHECKLIST.md`）一致
   - 价值：避免评审和发布阶段“同名 gate 不同解释”。

---

## 风险与回滚点（3项）

1. **风险：状态机语义冻结后仍存在边界迁移盲区**
   - 触发信号：event replay 通过，但出现新边界 case（如非法状态跳转）无法在门禁前暴露。
   - 回滚点：
     - 立即回到 `run_v1_protocol_gates.sh` + event field/replay 双门禁结果为唯一发布依据
     - 暂停“新增语义解释”，仅按已冻结 v1 文档口径执行。

2. **风险：timeout/retry 参数漂移导致“假失败/假成功”**
   - 触发信号：worker gate 在不同环境结果不一致（尤其 real-cli 与 command 模式）。
   - 回滚点：
     - 回退到默认 strict 口径（`REQUIRE_REAL_TX_CLI=1` 的既有流程）
     - 禁止临时放宽 retry/timeout 阈值进入发布判断。

3. **风险：gate 通过但证据链不完整，导致 RC 不可审计**
   - 触发信号：日志有“通过”结论，但缺少 streak/evidence 文件或路径不可追溯。
   - 回滚点：
     - 不打 RC tag；回到 `release_rc.sh` 标准产物清单重跑
     - 以 `manifest + nightly-streak + state-root audit` 三件套作为最小放行前置。

---

## 备注（与当前现状对齐）

- 仓库已具备 v1 主路径与多项硬门禁基础；本计划不引入新代码工作，重点是**证据闭环与口径收敛**。
- 执行优先级：**先语义门禁（state machine/event），再 timeout/retry 运行口径，最后性能与发布打包**。