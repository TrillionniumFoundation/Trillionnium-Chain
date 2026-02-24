# Manual Merge Gate Checklist（方案 B）

更新日期：2026-02-19  
适用场景：仓库暂无法启用 GitHub required checks（私有仓库套餐限制）时，作为临时合并门禁。

---

## 使用规则（必须遵守）

- 任何合并到 `main` 前，必须完成本清单并附证据。
- 任一 gate 不通过：**禁止合并**。
- 证据路径必须可复现（`data/.../summary.json`）。

---

## 1) Pre-merge 基线

- [ ] 工作区干净：`git status --short`
- [ ] 本地已同步远端：`git fetch origin && git rebase origin/main`（或等价流程）
- [ ] 记录提交：`git rev-parse --short HEAD`

---

## 2) 快速静态门禁（Quick Gate）

- [ ] 运行：

```bash
./scripts/quick_gate_shell.sh scripts trillionnium-rust/scripts
WORKFLOW_SCRIPT_REF_STRICT=0 ./scripts/validate_workflow_script_refs.sh
# 建议同时输出结构化摘要（便于留档/比对）：
# QUICK_GATE_SUMMARY_PATH=run/quick-gate/summary.json ./scripts/quick_gate_shell.sh scripts trillionnium-rust/scripts
# WORKFLOW_SCRIPT_REF_STRICT=0 WORKFLOW_SCRIPT_REF_SUMMARY_PATH=run/quick-gate/workflow-script-refs-summary.json ./scripts/validate_workflow_script_refs.sh
# 若本机未安装 shellcheck，可先做语法预检：
# QUICK_GATE_SKIP_SHELLCHECK=1 ./scripts/quick_gate_shell.sh scripts trillionnium-rust/scripts
```

- [ ] 结果：无 error
- [ ] （可选）归档 Quick Gate 结构化摘要：
  - `run/quick-gate/summary.json`
  - `run/quick-gate/workflow-script-refs-summary.json`
  - 建议核对：`target_dir_count`、`script_count`、`file_manifest_sha256`、`missing_count`、`non_exec_count`（便于复盘一致性）

---

## 3) 功能门禁（Hard Gate）

- [ ] 启动链（若未启动）

```bash
./build/chaind start --home ~/.chain --minimum-gas-prices 0stake
```

- [ ] 运行 P0：

```bash
./scripts/p0_merge_gate.sh
```

- [ ] 运行 P1（建议开启 Rust sidecar）：

```bash
WITH_RUST_VERIFY=1 ./scripts/p1_negative_suite.sh
```

- [ ] 验收阈值：
  - P0: `fail=0`
  - P1: `fail=0 && skip=0`
  - Rust sidecar（若启用）: `rust_verify_rc=0 && rust_verify_mismatch=0`

- [ ] 记录证据路径：
  - P0 summary: `data/p0-acceptance/<ts>/summary.json`
  - P1 summary: `data/p1-negative/<ts>/summary.json`
  - Rust output（若启用）: `data/rust-verifier-local/<ts>/`

- [ ] CI 证据（建议附上，advisory）
  - workflow: `.github/workflows/p1-rust-sidecar.yml`
  - run artifact: `p1-rust-sidecar-artifacts-<run_id>`

---

## 4) 合并说明模板（复制即用）

```markdown
## Manual Gate Evidence (Plan B)
- Commit: <sha>
- P0: <path-to-summary.json> (fail=0)
- P1: <path-to-summary.json> (fail=0, skip=0)
- Quick Gate: bash -n + shellcheck -S error passed
- Operator: <name>
- Time: <YYYY-MM-DD HH:mm TZ>
```

---

## 5) 失效条件（何时停止使用方案 B）

以下任一满足，立即切回平台强制门禁：

1. 仓库升级到可用 branch protection/ruleset 的套餐；
2. 仓库转为 public 并启用 required checks；
3. 引入组织级规则可替代人工门禁。
