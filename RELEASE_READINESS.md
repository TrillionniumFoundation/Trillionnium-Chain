# TRNM Release Readiness

更新日期：2026-03-09
适用范围：仓库根目录当前状态（`fix/integrate-challenge-wave-20260309` / `fcfc0e5d` 基线衍生 worktree）

> 本文件是当前**唯一权威**的发布/就绪状态摘要。
> - `STATUS.md`：保留为历史推进日志，不作为当前 release truth source。
> - `docs/development/GO_READY_EVIDENCE_WEB4_2026-03-03.md`、`docs/release/web4-fix-sequence-2026-03-04-evidence.md`：仅表示当时那一轮修复/门禁证据，不等于今天整个仓库已可发布。

## 当前结论

**结论：Not release-ready / 不应对外宣称“已发布就绪”。**

当前仓库具备若干可复用的局部门禁、历史证据包与前端发布前检查脚本，但仍存在会误导读者的 truth-source drift：

1. `STATUS.md` 顶部仍以“可发布基线视角”描述 2026-02-21 状态，时间上已失效。
2. 根 `README.md` 曾把 Web4 发布前脚本写成仓库根 `scripts/*.sh`，但这些路径当前并不存在；实际脚本位于 `web4-frontend/scripts/`。
3. Web4 的“GO-ready / PASS”文档是**历史轮次证据**，不能直接外推为整个仓库当前 release-ready。
4. verifier 相关旧 PoC 本体（如 `rust/verifier`、`scripts/run_rust_verifier_poc.sh`）当前不存在；若文档仍给人“已内建并持续受保护”的印象，会造成错误预期。
5. Web4 仪表盘仍存在本地数据源实现（`web4-frontend/app/dashboard-data.ts`），因此前端更接近“门禁与界面可演示/可校验”，而非默认可视为链上真实生产态。

## 分项状态

### 1. Rust L1 / 主链
- **状态**：开发中，已有较多 gate / replay / benchmark / nightly 文档与脚本。
- **可确认事实**：仓库内存在 `trillionnium-rust/scripts/release_rc.sh`、`trillionnium-rust/scripts/run_local_release_evidence.sh` 等 release 相关脚本。
- **当前不应宣称**：整个仓库已达到统一 release-ready。

### 2. Web4 前端
- **状态**：有独立 `npm` 发布前检查链路，但就绪范围应限定为“前端子项目预检”。
- **可确认事实**：`web4-frontend/package.json` 中 `ci:check` / `release:preflight` / `release:ready` 均存在，并调用 `web4-frontend/scripts/*.sh`。
- **限制**：存在历史“GO-ready”证据包；同时文档明确保留过 `dashboard-data.ts` 本地数据源语义，因此不能把 Web4 当前状态笼统写成“生产就绪”。

### 3. Verifier / sidecar
- **状态**：旧 Rust verifier PoC 本体不在当前仓库中。
- **可确认缺失**：`rust/verifier`、`scripts/run_rust_verifier_poc.sh`、`docs/protocol/rust-verifier-poc.md` 当前不存在。
- **文档口径**：仅可表述为“存在历史旁路复验/证据记录”，不可表述为“当前仓库内建 verifier 子系统已就绪”。

## 文档使用规则（新的 truth-source 结构）

1. **当前是否可发布**：先看本文件 `RELEASE_READINESS.md`。
2. **历史推进与里程碑**：看 `STATUS.md`。
3. **某一轮 Web4 / release 修复是否跑通过**：看对应 `docs/development/*evidence*.md`、`docs/release/*evidence*.md`。
4. **子项目操作说明**：
   - 仓库总览：`README.md`
   - Web4 子项目：`web4-frontend/README.md`

## RC 演练最小证据模板（不发布）

> 目标：只做可回滚的 RC 就绪演练，禁止 release/tag/publish。

- **CI/门禁命令**：记录本轮执行的最小命令（含退出码）。
- **回放证据**：记录输入快照与输出摘要路径（例如 `run/local-release-evidence/` 下产物）。
- **回滚命令**：每轮必须给出单行回滚命令（例如 `git revert <commit>` 或文档改动的 `git checkout -- <file>`）。
- **根因标签**：失败时使用统一标签（建议：`CI_FLAKE` / `ENV_DRIFT` / `DOC_DRIFT` / `MISSING_FIXTURE`）。

建议在每轮提交信息或随附说明中使用固定字段：`gate`、`evidence`、`rollback`、`root_cause`，便于后续审计与自动汇总。

## 仍然 deferred / 未在本次文档修正中解决

1. 未重新执行整仓 release 级门禁，也未重新生成新的 closeout bundle。
2. 未对所有历史文档逐篇改写，只对最容易造成“当前已就绪”误解的入口文档做了降级说明。
3. 未在本次工作中改变代码或发布脚本行为；本次仅收口 truth-source 与文档口径。
