# Trillionnium Alpha Demo Runbook

> 目的：一条命令跑通最小可演示闭环，并验证解质押冷却保护未被绕过。

## 0. 前置条件
- 已构建链二进制：`build/chaind`
- 本地链已启动（RPC: `tcp://127.0.0.1:26657`）
- 测试 key 已导入（默认 `alice` 作为 worker）
- Python worker 可运行（`worker/main.py`）

## 1. 快速开始（一键）
在仓库根目录执行：

```bash
MODE=full COUNT=2 ./scripts/demo_e2e.sh
```

默认会执行两段：
1. **happy path**：提交任务并等待 worker 上链提交结果
2. **unbonding guard**：请求解质押后立刻 finalize（预期失败）

## 2. 常用模式
仅跑 happy path：

```bash
MODE=happy COUNT=3 ./scripts/demo_e2e.sh
```

仅跑解质押冷却检查：

```bash
MODE=unbonding ./scripts/demo_e2e.sh
```

## 3. 可调参数（环境变量）
- `CHAIN_ID`（默认 `trillionnium`）
- `HOME_DIR`（默认 `/Users/qianqi/.chain`）
- `NODE`（默认 `tcp://127.0.0.1:26657`）
- `WORKER_KEY`（默认 `alice`）
- `COUNT`（默认 `2`）
- `MODE`（`happy | unbonding | full`）

## 4. 预期输出
- happy path 结束时应看到：`SMOKE PASS ✅`
- unbonding 检查应看到：`✅ Cooldown guard works: early finalize-unbonding rejected`

## 5. 故障排查
1. **链未启动**：
   - 报错通常发生在 `chaind status` 阶段
   - 先确认本地节点进程是否在线
2. **worker 未提交结果**：
   - 查看 `worker/worker.log`
   - 检查 Docker 是否可用
3. **交易 sequence mismatch**：
   - 脚本内已有重试（happy path 由 `e2e_smoke.sh` 处理）
4. **unbonding 检查意外通过**：
   - 说明冷却参数或逻辑异常，应立刻复核 keeper 逻辑和参数

## 6. 与验收矩阵对应关系
- 场景 A：正常完成 → `MODE=happy`
- 场景 E：解质押冷却与提现（前半段：冷却前拒绝）→ `MODE=unbonding`

完整 5 场景矩阵见：`docs/alpha-runs/TEST_ACCEPTANCE_MATRIX.md`
