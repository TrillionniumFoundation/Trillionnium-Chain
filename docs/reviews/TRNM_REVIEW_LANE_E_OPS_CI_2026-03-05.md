# TRNM Lane E（Ops/CI/Recovery）复审报告

- 复审时间：2026-03-05
- 复审范围：`.github/workflows`、`scripts/`、`trillionnium-rust/scripts`、runbooks、release 证据链
- 复审方式：静态审查 + 关键脚本可执行性检查（`./scripts/validate_workflow_script_refs.sh`）

---

## 一、证据链快照（本次复审执行）

1. 工作流脚本引用检查已重跑：
   - 命令：`./scripts/validate_workflow_script_refs.sh`
   - 结果：`workflow_count=10`，`script_ref_count=133`，`status=ok`（strict=0）
2. 发现 10/10 workflow 未声明 `permissions:`（通过 grep 扫描）
3. 发现 actions 统一使用 tag（如 `@v4/@v5/@stable`），未固定到 commit SHA

---

## 二、Challenges（>=8，含证据路径 + 触发方式 + 建议）

### Challenge E-01（P0）
- **问题**：所有 workflow 缺失最小权限声明（`permissions:`），默认 token 权限过宽。
- **证据路径**：
  - `.github/workflows/*.yml`（10 个文件均无 `permissions:`）
- **触发方式**：
  - `for f in .github/workflows/*.yml; do if ! grep -q '^permissions:' "$f"; then echo "$f"; fi; done`
- **建议**：
  - 所有 workflow 顶层添加最小权限（默认 `contents: read`），按需对单 job 提升；禁止隐式默认权限。

### Challenge E-02（P0）
- **问题**：第三方/官方 actions 未 pin 到 commit SHA，存在供应链漂移风险。
- **证据路径**：
  - `.github/workflows/*.yml`，如：`actions/checkout@v4`、`actions/setup-go@v5`、`dtolnay/rust-toolchain@stable`
- **触发方式**：
  - `grep -R "uses:" .github/workflows | grep -v '@[0-9a-f]\{40\}'`
- **建议**：
  - 统一改为 `uses: owner/repo@<40位SHA>`，并用 Dependabot/Renovate 管理升级 PR。

### Challenge E-03（P0）
- **问题**：P1 侧车流水线将核心 gate 标记为 `continue-on-error: true`，失败可“绿过”。
- **证据路径**：
  - `.github/workflows/p1-rust-sidecar.yml:43-49`
- **触发方式**：
  - `nl -ba .github/workflows/p1-rust-sidecar.yml | sed -n '39,50p'`
- **建议**：
  - 上线分支/受保护分支必须 hard-fail；如需观测模式，拆分为独立 advisory workflow，不得混入 release blocking gate。

### Challenge E-04（P1）
- **问题**：P1 workflow 的 `paths` 触发集合过窄，关键实现文件变更可能绕过此 CI。
- **证据路径**：
  - `.github/workflows/p1-rust-sidecar.yml:6-19`
- **触发方式**：
  - 查看 `paths` 仅覆盖少量脚本、sdk 示例和单测试文件
- **建议**：
  - 扩展路径到相关 crate/模块目录，或改成由 `trnm-merge-gates` 统一强制覆盖。

### Challenge E-05（P1）
- **问题**：nightly workflow 使用 `concurrency.cancel-in-progress: true`，定时任务可能被后续触发中断，证据链不连续。
- **证据路径**：
  - `.github/workflows/rust-l1-nightly-health.yml:12-14`
- **触发方式**：
  - `nl -ba .github/workflows/rust-l1-nightly-health.yml | sed -n '12,14p'`
- **建议**：
  - 对 schedule 类任务禁用 cancel-in-progress，或按 `run_id/date` 分组防止覆盖。

### Challenge E-06（P1）
- **问题**：nightly 中多个 ops 关键输出步骤 `continue-on-error: true`，失败仅“可见”不阻断，易形成“报告缺失但总流水线通过”。
- **证据路径**：
  - `.github/workflows/rust-l1-nightly-health.yml`（多处：PR5/PR6/PR9/P11/PR7 summary append）
- **触发方式**：
  - `grep -n "continue-on-error: true" .github/workflows/rust-l1-nightly-health.yml`
- **建议**：
  - 区分“可选报告”与“发布必要证据”；必要证据生成失败应 hard-fail（至少在 release candidate 流）。

### Challenge E-07（P1）
- **问题**：BFT 恢复脚本使用 `kill -9` 强杀 + 单 WAL 目录跨轮复用，可能引入污染/偶发假阳性。
- **证据路径**：
  - `trillionnium-rust/scripts/check_bft_restart_recovery.sh:12,38,16-19`
- **触发方式**：
  - `nl -ba trillionnium-rust/scripts/check_bft_restart_recovery.sh | sed -n '12,60p'`
- **建议**：
  - 每轮独立 WAL 目录；优先 SIGTERM + 超时升级 SIGKILL；在报告中记录每轮 WAL hash 与恢复高度。

### Challenge E-08（P1）
- **问题**：本地 release 证据脚本用“模糊匹配首个 challenge reexec 入口”，可重复性不足。
- **证据路径**：
  - `trillionnium-rust/scripts/run_local_release_evidence.sh:67-74,107-109`
- **触发方式**：
  - `nl -ba trillionnium-rust/scripts/run_local_release_evidence.sh | sed -n '67,110p'`
- **建议**：
  - 显式固定入口脚本（参数化但需 allowlist），禁止 `find|head -n1` 非确定性选择。

### Challenge E-09（P0）
- **问题**：release closeout 文档使用短 SHA 且无 artifact digest/run_id 绑定，不满足强审计可追溯。
- **证据路径**：
  - `docs/archive/web4-history/web4-closeout-bundle-2026-03-04.md:5-9,19-31`
- **触发方式**：
  - `nl -ba docs/archive/web4-history/web4-closeout-bundle-2026-03-04.md | sed -n '1,40p'`
- **建议**：
  - 统一使用 40 位 commit SHA + GitHub run_id/run_attempt + artifact SHA256 清单；补“证据索引清单（manifest）”。

### Challenge E-10（P1）
- **问题**：Web4 release 聚合 gate 允许通过环境变量重写 required gates，流程上存在“误配置降级覆盖面”的风险。
- **证据路径**：
  - `scripts/v2/web4_release_aggregate_gate.sh:7,31-42`
- **触发方式**：
  - `WEB4_RELEASE_REQUIRED_GATES='scripts/v2/x2_settlement_contract_gate.sh' ./scripts/v2/web4_release_aggregate_gate.sh`
- **建议**：
  - 在 CI 发布模式下禁用 override（或只允许超集）；增加 `--strict-release` 模式强制默认全量 gate。

### Challenge E-11（P1）
- **问题**：RC 发布脚本允许 `SKIP_STREAK_CHECK=1` 跳过“nightly 连绿”前置门禁，易被临时绕过固化为习惯。
- **证据路径**：
  - `trillionnium-rust/scripts/release_rc.sh:12-17`
- **触发方式**：
  - `SKIP_STREAK_CHECK=1 trillionnium-rust/scripts/release_rc.sh`
- **建议**：
  - 仅允许在本地 debug 使用；CI/release 环境下强制禁止该变量（检测到即 fail）。

---

## 三、上线前必补清单

### P0（必须先补，未完成禁止上线）
1. **最小权限落地**：所有 workflow 增加 `permissions:`，默认 `contents: read`。
2. **Actions 供应链加固**：所有 `uses:` pin 到 commit SHA（含 `dtolnay/rust-toolchain`）。
3. **阻断型 gate 不能软失败**：`p1-rust-sidecar` 的核心 gate 去掉 `continue-on-error: true`。
4. **Release 证据链可追溯**：closeout 文档补全 40 位 SHA、run_id、artifact hash manifest。

### P1（上线后首迭代必须补）
1. 扩展 `p1-rust-sidecar` 的 `paths` 覆盖，避免变更漏检。
2. nightly 并发策略调整，避免 schedule 任务被取消导致证据断档。
3. `run_local_release_evidence.sh` 去非确定性入口发现逻辑，改显式入口。
4. `check_bft_restart_recovery.sh` 每轮独立 WAL + 优雅终止流程。
5. `web4_release_aggregate_gate.sh` 在 CI 发布模式禁用 gate 列表降级覆盖。
6. `release_rc.sh` 在 CI 中禁止 `SKIP_STREAK_CHECK`。

---

## 四、结论

Lane E 当前“可运行”，但离“可审计、可阻断、可追责”的上线标准尚有明显差距。核心短板集中在：
- **CI 权限与供应链基线缺失（P0）**
- **阻断门禁软失败（P0）**
- **release 证据链不可强追溯（P0）**

建议按上文 P0 清单先完成并复核，再进入上线窗口。
