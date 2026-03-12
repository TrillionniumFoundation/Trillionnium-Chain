# TRNM Release Readiness

更新日期：2026-03-10
适用范围：`origin/main` 当前快照（`0b209289`）

> 本文件是当前 **release readiness truth source**，且仅对上面标明的 `origin/main` 快照负责。
> - `STATUS.md`：历史推进日志 / working journal，不参与当前 release 判定。
> - `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`：开发调度板，不覆盖发布口径。
> - `docs/development/GO_READY_EVIDENCE_WEB4_2026-03-03.md`、`docs/release/web4-fix-sequence-2026-03-04-evidence.md`：仅表示当时那一轮修复/门禁证据，不等于今天整个仓库已可发布。

## 当前结论

**结论：Not release-ready / 不应对外宣称“已发布就绪”。**

当前仓库具备若干可复用的局部门禁、历史证据包与前端发布前检查脚本，但仍存在会误导读者的 truth-source drift：

1. `STATUS.md` 顶部仍以“可发布基线视角”描述 2026-02-21 状态，时间上已失效。
2. 根 `README.md` 曾把 Web4 发布前脚本写成仓库根 `scripts/*.sh`，但这些路径当前并不存在；实际脚本位于 `web4-frontend/scripts/`。
3. Web4 的“GO-ready / PASS”文档是**历史轮次证据**，不能直接外推为整个仓库当前 release-ready。
4. verifier 相关旧 PoC 本体（如 `rust/verifier`、`scripts/run_rust_verifier_poc.sh`）当前不存在；若文档仍给人“已内建并持续受保护”的印象，会造成错误预期。
5. Web4 当前真实语义是“**readonly API client + explicit mock fallback**”：页面默认尝试只读查询客户端；只有在显式 `?mode=mock` 时才回退到本地 snapshot，因此不能把它写成“纯静态 mock 页面”，也不能写成“已接通仓内写路由的生产后台”。
6. 文档中出现的 `/api/v0/web4/*` 属于历史 V0 草案命名；当前仓内并没有对应的 Next.js/仓内 route，实现语义应以 `web4-frontend/lib/api-contract/*` 与 `web4-frontend/lib/dashboard/source.ts` 的只读客户端为准。
7. 并发 closeout / 对外对标目前也仍处于文档收口阶段：`docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md` 是当前瓶颈图与 8 周路线入口，`docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md` 是对外口径草案；二者用于说明“当前到哪一步”，**不是** release-ready 证明。

## 分项状态

### 1. Rust L1 / 主链
- **状态**：开发中，已有较多 gate / replay / benchmark / nightly 文档与脚本。
- **可确认事实**：仓库内存在 `trillionnium-rust/scripts/release_rc.sh`、`trillionnium-rust/scripts/run_local_release_evidence.sh` 等 release 相关脚本。
- **当前不应宣称**：整个仓库已达到统一 release-ready。

### 2. Web4 前端
- **状态**：有独立 `npm` 发布前检查链路；前端运行语义为只读查询客户端，失败时 fail-closed，开发/演示场景可显式切到 mock fallback。
- **可确认事实**：`web4-frontend/package.json` 中 `ci:check` / `release:preflight` / `release:ready` 均存在，并调用 `web4-frontend/scripts/*.sh`；`web4-frontend/lib/api-contract/client.ts` 实际消费 `GET /query-task/:taskId`、`GET /query-events/:taskId`、`GET /query-capability-audit/:subject`。
- **限制**：存在历史“GO-ready”证据包；当前仓内也没有 `/api/v0/web4/*` 对应实现，因此不能把 Web4 当前状态笼统写成“生产就绪”或“仓内 dashboard API 已落地”。

### 3. Verifier / sidecar
- **状态**：旧 Rust verifier PoC 本体不在当前仓库中。
- **可确认缺失**：`rust/verifier`、`scripts/run_rust_verifier_poc.sh`、`docs/protocol/rust-verifier-poc.md` 当前不存在。
- **文档口径**：仅可表述为“存在历史旁路复验/证据记录”，不可表述为“当前仓库内建 verifier 子系统已就绪”。

## 文档使用规则（新的 truth-source 结构）

1. **当前是否可发布**：先看本文件 `RELEASE_READINESS.md`。
2. **开发排期 / lane 调度 / 下一步执行**：看 `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`。
3. **ZKP 平台边界 / backend 抽象 / payload 与错误契约**：看 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`。
4. **benchmark closeout 方法、统一产物、micro→system bridge**：看 `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`。
5. **并发架构现状 / 对外对标口径 / 8 周路线**：
   - 当前瓶颈图与 8 周路线：`docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md`
   - TRNM vs Solana vs Sui 对比口径：`docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md`
6. **历史推进与里程碑**：看 `STATUS.md`。
7. **某一轮 Web4 / release 修复是否跑通过**：看对应 `docs/development/*evidence*.md`、`docs/release/*evidence*.md`。
8. **子项目操作说明**：
   - 仓库总览：`README.md`
   - Web4 子项目：`web4-frontend/README.md`

## RC 演练最小证据模板（不发布）

> 目标：只做可回滚的 RC 就绪演练，禁止 release/tag/publish。

- **CI/门禁命令**：记录本轮执行的最小命令（含退出码）。建议统一加 deterministic 前缀：`env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200`。
  - Rust 侧示例：`env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200 cargo test -p trnm-rpc --test reliability_persistent_smoke -- --nocapture`
- **确定性复跑**：同一 gate 至少连续执行 2 次（命令与环境完全一致）并记录结果，避免一次性绿灯掩盖 flaky。
- **回放证据**：记录输入快照与输出摘要路径（例如 `run/local-release-evidence/` 下产物），并附 `date -u +"%Y-%m-%dT%H:%M:%SZ"` 时间戳。
- **回滚命令**：每轮必须给出单行回滚命令（例如 `git revert <commit>` 或文档改动的 `git checkout -- <file>`）。
- **根因标签**：失败时使用统一标签（建议：`CI_FLAKE` / `ENV_DRIFT` / `DOC_DRIFT` / `MISSING_FIXTURE` / `NON_DETERMINISTIC_TEST`）。

建议在每轮提交信息或随附说明中使用固定字段：`gate`、`evidence`、`rollback`、`root_cause`，便于后续审计与自动汇总。

L04 observability note: when reviewing consensus-loop regressions, prefer height-aware jitter indicators such as `bft_round_change_density_avg_milli` together with `bft_round_change_backoff_density_avg_milli`, and use `bft_round_change_active_heights` / `bft_round_change_backoff_active_heights` plus `bft_round_change_active_height_share_ppm` / `bft_round_change_backoff_active_height_share_ppm` to relate clustered jitter to average finality budget instead of letting it disappear inside global averages. Keep `bft_round_change_backoff_wall_share_ppm` and its compatibility alias `bft_round_change_backoff_share_ppm` separate from that budget-share view: they track total backoff wall time per committed height, not the per-active-height budget pressure signal, so they should be compared with the active-height-share fields rather than substituted for them. If skipped/no-commit heights are present, compare the committed-budget view (`bft_round_change_active_height_rate_ppm`) with the coverage view (`bft_round_change_active_observed_height_rate_ppm`, denominator = `bft_observed_heights`) so jitter does not look artificially compressed or inflated depending on how many heights actually committed. Read that pair together with `bft_commit_observed_height_rate_ppm` and `bft_skipped_observed_height_rate_ppm`: they expose whether the apparent improvement is just a denominator shift caused by fewer committed heights rather than a real reduction in jitter pressure. Apply the same coverage check to sustained backoff bursts by pairing `bft_round_change_backoff_active_height_rate_ppm` with `bft_round_change_backoff_active_observed_height_rate_ppm` before using wall-share or budget-share fields to judge severity, and keep the active-height counts nearby so burst width is visible instead of inferred indirectly from rates alone. For proposer fairness hotspots, also review `bft_leader_missed_active_validators` and `bft_leader_missed_active_validator_share_ppm` alongside `bft_leader_missed_top_share_ppm`, plus `bft_leader_missed_active_heights` / `bft_leader_missed_active_height_rate_ppm`, `bft_leader_missed_active_observed_height_rate_ppm`, `bft_leader_missed_density_avg_milli`, and `bft_leader_missed_active_height_share_ppm`, so concentrated misses do not hide behind raw totals, a benign-looking end-state validator distribution, or an apparently acceptable global finality average. In particular, do not substitute the validator-spread view (`bft_leader_missed_active_validator_share_ppm`) for the active-height budget view (`bft_leader_missed_active_height_share_ppm`): the former answers how widely missed proposals have spread across proposers, while the latter answers how much burst pressure those misses impose on the average finality budget at the heights where they actually occur. Treat scheduler fairness stalls the same way: pair `critical_wait_active_heights`, `critical_wait_active_height_rate_ppm`, and `critical_wait_active_observed_height_rate_ppm` with `critical_wait_density_avg_milli`, `critical_wait_peak_density_ppm`, and `critical_wait_active_height_share_ppm` so queueing bursts that only hit a few heights do not disappear inside global averages or look benign just because the overall committed-height share stays moderate. For hot-object concentration, pair `hot_object_active_heights`, `hot_object_active_height_rate_ppm`, `hot_object_active_observed_height_rate_ppm`, and `hot_object_active_height_share_ppm` with `hot_object_share_*`, `hot_object_top_label_share_*`, `hot_object_active_top_label_share_avg_ppm`, `hot_object_tail_share_*`, and `hot_object_active_tail_share_avg_ppm` so a bursty hotspot does not disappear inside committed-height averages or look benign just because the dominant label share and tail share are read in isolation; `hot_object_active_height_share_ppm` is the budget-pressure companion to the coverage view, not a replacement for the top/tail split. For preexec/rollback guardrails, review `preexec_peak_share_ppm`, `preexec_reject_active_heights`, `preexec_reject_density_avg_milli`, `preexec_reject_active_height_rate_ppm`, `preexec_reject_active_observed_height_rate_ppm`, `preexec_reject_active_height_share_ppm`, `preexec_reject_share_bps`, and `preexec_conflict_miss_share_bps` together with `preexec_elapsed_*`, then pair `rollback_peak_share_ppm`, `rollback_active_heights`, `rollback_density_avg_milli`, `rollback_active_height_share_ppm`, `rollback_active_height_rate_ppm`, `rollback_active_observed_height_rate_ppm`, `apply_error_rollback_share_bps`, `bft_commit_observed_height_rate_ppm`, and `bft_skipped_observed_height_rate_ppm`; this avoids treating concentrated guardrail pressure as harmless because global average finality still looks acceptable or because skipped heights silently changed the denominator.

## 仍然 deferred / 未在本次文档修正中解决

1. 未重新执行整仓 release 级门禁，也未重新生成新的 closeout bundle。
2. 未对所有历史文档逐篇改写，只对最容易造成“当前已就绪”误解的入口文档做了降级说明。
3. 未在本次工作中改变代码或发布脚本行为；本次仅收口 truth-source 与文档口径。
