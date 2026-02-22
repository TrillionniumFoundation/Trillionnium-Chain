# Gate 稳定性证据包草案（2026-02-22）

范围：`trillionnium-rust` 下已存在的 gate 入口（binding / fault-injection / nightly / streak）

> 目标：形成可复跑、可判定、可留痕的最小证据包模板；不改核心代码。

---

## 1) 已有 gate 脚本入口汇总

建议在仓库根目录执行时先进入：

```bash
cd trillionnium-rust
```

### A. Request -> TX Binding Gate
- 入口脚本：`scripts/check_request_tx_binding.sh`
- 作用：提交请求并走 worker 执行/flush，验证 `commit_tx_hash` 与 `reveal_tx_hash` 已正确绑定。
- 证据文件（脚本自动生成）：
  - `run/health/request-tx-binding-<YYYYmmdd-HHMMSS>.txt`

执行命令：
```bash
./scripts/check_request_tx_binding.sh
```

预期输出（终端关键字）：
- `[OK] request tx binding passed: ...`

失败判定：
- 退出码非 0；或
- 输出含 `[FAIL] missing commit_tx_hash`；或
- 输出含 `[FAIL] missing reveal_tx_hash`。

---

### B. Request Fault Injection Gate
- 入口脚本：`scripts/run_request_fault_injection.sh`
- 作用：对 adapter 场景做注入（`ok / invalid_json / too_long`）并记录请求最终状态、verifier 状态与 resolution code。
- 证据文件（脚本自动生成）：
  - `run/health/request-fault-injection-<YYYYmmdd-HHMMSS>.txt`

执行命令：
```bash
./scripts/run_request_fault_injection.sh
```

预期输出（终端关键字）：
- `[OK] request fault injection report: ...`

失败判定：
- 脚本异常退出（退出码非 0）。

建议人工复核（证据文件内）：
- 至少包含 `case=ok / invalid_json / too_long` 三段；
- 每段具备 `status=`、`verifier_status=`、`resolution_code=` 字段。

---

### C. Nightly Green Streak Gate（核心 streak 判定）
- 入口脚本：`scripts/check_nightly_green_streak.sh [owner] [repo] [required_streak]`
- 作用：检查 GitHub workflow `rust-l1-nightly-health.yml` 最近完成运行的连续成功次数。
- 默认参数：`ProfAlexQI TrillionniumChain 3`
- 证据文件：
  - 脚本默认写 stdout；建议重定向留痕到：
  - `run/health/nightly-streak-<YYYYmmdd-HHMMSS>.txt`

执行命令（推荐留痕）：
```bash
TS=$(date +%Y%m%d-%H%M%S)
./scripts/check_nightly_green_streak.sh ProfAlexQI TrillionniumChain 3 \
  | tee "run/health/nightly-streak-${TS}.txt"
```

预期输出（关键字段）：
- `nightly.workflow=rust-l1-nightly-health.yml`
- `nightly.green_streak=<N>`
- `nightly.required_streak=3`
- `nightly green streak check: PASS`

失败判定：
- 退出码非 0；或
- 出现 `nightly green streak insufficient`；或
- `nightly.green_streak < nightly.required_streak`。

---

### D. Industrial Readiness Wrapper（nightly/streak 聚合入口）
- 入口脚本：`scripts/run_industrial_readiness_check.sh [owner] [repo] [required_streak]`
- 作用：封装 nightly streak 检查并自动产出总报告。
- 证据文件（脚本自动生成）：
  - `run/health/industrial-readiness-<YYYYmmdd-HHMMSS>.txt`

执行命令：
```bash
./scripts/run_industrial_readiness_check.sh ProfAlexQI TrillionniumChain 3
```

预期输出（关键字）：
- `industrial_readiness.result=PASS`
- `[OK] industrial readiness report: ...`

失败判定：
- 退出码非 0；或
- 报告中未出现 `industrial_readiness.result=PASS`。

---

## 2) 证据文件路径模板（可直接复用）

- `trillionnium-rust/run/health/request-tx-binding-<YYYYmmdd-HHMMSS>.txt`
- `trillionnium-rust/run/health/request-fault-injection-<YYYYmmdd-HHMMSS>.txt`
- `trillionnium-rust/run/health/nightly-streak-<YYYYmmdd-HHMMSS>.txt`（由 tee 重定向生成）
- `trillionnium-rust/run/health/industrial-readiness-<YYYYmmdd-HHMMSS>.txt`

可选附加证据（故障定位）：
- `/tmp/fault-run-<case>.log`
- `/tmp/trnm-worker-agent-submissions-*.jsonl`
- `/tmp/trnm-worker-agent-acks-*.jsonl`
- `/tmp/trnm-worker-agent-events-*.jsonl`
- `/tmp/trnm-worker-agent-progress-*.jsonl`

---

## 3) 最小每日执行清单（早/晚两次）

> 建议时段：09:30（早）/ 20:30（晚），均在 `trillionnium-rust` 目录执行。

### 早间（快速健康检查）
1. Nightly streak（硬门槛）
   ```bash
   TS=$(date +%Y%m%d-%H%M%S)
   ./scripts/check_nightly_green_streak.sh ProfAlexQI TrillionniumChain 3 \
     | tee "run/health/nightly-streak-${TS}.txt"
   ```
2. Request->TX binding gate
   ```bash
   ./scripts/check_request_tx_binding.sh
   ```

通过标准（早间）：
- streak 达标（`PASS`）；
- binding 输出 `[OK]` 且证据文件存在。

### 晚间（稳定性+抗异常复验）
1. Fault injection gate
   ```bash
   ./scripts/run_request_fault_injection.sh
   ```
2. Industrial readiness 聚合检查
   ```bash
   ./scripts/run_industrial_readiness_check.sh ProfAlexQI TrillionniumChain 3
   ```

通过标准（晚间）：
- fault-injection 输出 `[OK]` 且报告含三类 case；
- industrial-readiness 报告标记 `industrial_readiness.result=PASS`。

---

## 4) 失败升级建议（简版）

任一 gate 失败时：
1. 保留当次 `run/health/*.txt` + `/tmp/fault-run-*.log`；
2. 在同日 `docs/reports/` 新建短报告（失败时间、命令、退出码、关键日志）；
3. 暂停“工业级可用”对外声明，待连续复跑恢复后再放行。

---

本文件为证据包草案，可作为后续 RC evidence 包的骨架模板。