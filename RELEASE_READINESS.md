# TRNM Release Readiness

更新日期：2026-03-28
适用范围：引用本文件时，必须同时记录当下的 `git rev-parse origin/main` 输出；不要继续把旧文档头中的固定 commit hash 当作长期 truth source。

> 本文件是当前 **release readiness truth source**。
> 在 release / RC / handoff 语境引用本文件时，必须把当时的 `origin/main` commit 与本文件一起记录，避免把过期快照误当成当前结论。
> - `docs/archive/root-history/STATUS.md`：历史推进日志 / working journal，不参与当前 release 判定。
> - `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`：开发调度板，不覆盖发布口径。
> - `docs/archive/web4-history/GO_READY_EVIDENCE_WEB4_2026-03-03.md`、`docs/archive/web4-history/web4-fix-sequence-2026-03-04-evidence.md`：仅表示当时那一轮修复/门禁证据，不等于今天整个仓库已可发布。

## 当前结论

**结论：Not release-ready / 不应对外宣称“已发布就绪”。**

当前仓库具备若干可复用的局部门禁、历史证据包与前端发布前检查脚本，但仍存在会误导读者的 truth-source drift。

补充判读边界：
- `RELEASE_READINESS.md` 回答的是“当前仓库快照是否已经可以被表述为 release-ready / 对外可发布”。
- `trillionnium-rust/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` 回答的是“如果目标是 **public mainnet launch**，当前还缺哪些 P0/P1 blocker”。
- 因此，**local RC rehearsal PASS / validator handoff evidence 完整 / 某条子链路 GO-ready**，都不能单独外推为“public mainnet ready”。

当前主要误导风险包括：

1. `docs/archive/root-history/STATUS.md` 顶部仍以“可发布基线视角”描述 2026-02-21 状态，时间上已失效。
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
- **若需评估 P1.3 闭环程度**：请转到 `trillionnium-rust/docs/release/TRNM_VERIFIER_DA_CHECKPOINT_SIDECAR_CLOSURE_2026-03-31.md`，按 deployable boundary / DA-checkpoint linkage / failure taxonomy / replay evidence 逐项判读；该文档是 sidecar 收口清单，不是 release-ready 证明。

## 文档使用规则（新的 truth-source 结构）

1. **当前是否可发布**：先看本文件 `RELEASE_READINESS.md`。
2. **开发排期 / lane 调度 / 下一步执行**：看 `docs/development/DEVELOPMENT_MASTER_UNIFIED_2026-03-04.md`。
3. **ZKP 平台边界 / backend 抽象 / payload 与错误契约**：看 `docs/architecture/TRNM_ZKP_PLATFORM_V0.md`。
4. **benchmark closeout 方法、统一产物、micro→system bridge**：看 `docs/reports/TRNM_WEEK7_E2E_CLOSEOUT_BENCHMARK_SYSTEM_2026-03-10.md`。
5. **并发架构现状 / 对外对标口径 / 8 周路线**：
   - 当前瓶颈图与 8 周路线：`docs/reports/TRNM_CONCURRENCY_BOTTLENECK_MAP_AND_8W_ROADMAP_2026-03-10.md`
   - TRNM vs Solana vs Sui 对比口径：`docs/reports/TRNM_CONCURRENCY_COMPARISON_2026-03-05.md`
6. **历史推进与里程碑**：看 `docs/archive/root-history/STATUS.md`。
7. **某一轮 Web4 / release 修复是否跑通过**：看对应 `docs/archive/web4-history/*evidence*.md`。
8. **子项目操作说明**：
   - 仓库总览：`README.md`
   - Web4 子项目：`web4-frontend/README.md`
9. **RC / validator handoff 操作纪律**：看 `trillionnium-rust/docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`。
   - 适用场景：需要把 `testnet_preflight.sh`、`run_local_release_evidence.sh`、`release_rc.sh` 的产物交接给另一位 operator / validator 时。
   - 作用边界：它定义的是 artifact path 解析、identity 字段核对、replay/rollback 引用纪律；**不替代**本文件的 release readiness 结论。
10. **public mainnet blocker 判定 / P0-P1 收口顺序**：看 `trillionnium-rust/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`。
   - 适用场景：需要回答“距离 public mainnet 还差什么”“哪些属于 launch blocker”“Day-1 最小可信 scope 是什么”。
   - 作用边界：它是 mainnet closure matrix，不等于某一轮本地 RC/证据脚本已跑绿。
11. **主网值班可观测性最小包 / 告警与 incident handoff 约定**：看 `trillionnium-rust/docs/runbooks/mainnet-observability-alerting-starter-pack.md`，oracle 特定告警再配合 `trillionnium-rust/docs/runbooks/oracle-observability-alerts.md`。
   - 适用场景：需要冻结 `severity` / `signal` / `needs_replay` / `needs_rollback` 标签、最小 dashboard bundle、first-stop panel、以及 incident handoff 的 replay/rollback 指针。
   - 作用边界：它定义的是 **starter pack / 共享值班语义**，不等于 observability P0 已关闭，更不等于整个仓库 release-ready。
12. **把当前 36-lane 进展压成 launch-distance / GO-NO-GO 面板**：看 `trillionnium-rust/docs/release/TRNM_PUBLIC_MAINNET_GO_NO_GO_PANEL_2026-04-04.md`。
   - 适用场景：需要回答“结合当前 36-lane 提交代码，距离主网上线还有多远”“哪些已明显推进、哪些仍属硬 blocker、哪些可延后到 Day-1 之后”。
   - 作用边界：它是基于当下 lane snapshot 的**判断面板**，不是 release-ready 证明，也不替代 gap matrix 的长期 blocker taxonomy。
13. **判断 `MN01` 当前 residual 到底是“还没 merge 的真实工作”，还是“已被主线吸收 / superseded 的剩余 patch 形状”**：看 `trillionnium-rust/docs/release/TRNM_MN01_RESIDUAL_CLOSURE_2026-04-05.md`。
   - 适用场景：需要回答“`lane/mn01-peer-bootstrap-topology` 现在还剩多少是真正该继续手工吸收的”“哪些 recovery 提交不该再 merge”“为什么 `git cherry -v` 仍然显示很多 `+` 但语义上大多已被主线覆盖”。
   - 作用边界：它是**lane residual closure** 文档，不替代 broader launch-readiness truth source，也不意味着 `MN01` 可整体机械 merge。
14. **基于当前本地 integrated `main`（包括尚未推送到 `origin/main` 的本地吸收增量）重新评估“距离 public mainnet 还差多少”**：看 `trillionnium-rust/docs/release/TRNM_MAINNET_READINESS_REASSESSMENT_2026-04-05.md`。
   - 适用场景：需要回答“在当前本地 `main` 快照上，分支清理 / residual 吸收之后，项目离 public mainnet 到底还有多远”“当前最好阶段名是什么”“哪些 blocker 仍是最短发射路径上的硬约束”。
   - 作用边界：它评估的是**当前本地 integrated `main`**，因此必须连同当时的 `local main` commit 与 `origin/main` commit 一起引用；它不自动意味着远端 `origin/main` 已达到同一结论，也不替代本文件的总 release-ready 口径。

## RC 演练最小证据模板（不发布）

> 目标：只做可回滚的 RC 就绪演练，禁止 release/tag/publish。

- **CI/门禁命令**：记录本轮执行的最小命令（含退出码）。建议统一加 deterministic 前缀：`env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200`。
  - Rust 侧示例：`env TZ=UTC LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1704067200 cargo test -p trnm-rpc --test reliability_persistent_smoke -- --nocapture`
- **确定性复跑**：同一 gate 至少连续执行 2 次（命令与环境完全一致）并记录结果，避免一次性绿灯掩盖 flaky。
- **回放证据**：记录输入快照与输出摘要路径（例如 `trillionnium-rust/run/health/evidence-<timestamp>/` 下产物），并附 `date -u +"%Y-%m-%dT%H:%M:%SZ"` 时间戳。
- **复放命令来源**：若使用 `run_local_release_evidence.sh` 生成证据，优先直接引用 `summary.txt` 中生成的 `replay_command=` 字段，不要手工重写为缺少 deterministic 前缀或缺少 `TRNM_CHALLENGE_REEXEC_ENTRY` 固定值的裸命令。
- **环境字段判读**：`summary.txt` 中的 `env_*` 表示本次实际执行时生效的环境，可能保留调用者外层 shell 的预设值；`replay_env_*` 才是用于二次复放/审计引用的确定性基线。需要复跑或在文档中引用命令时，应优先采用 `replay_env_*` 与 `replay_command=`，不要把一次性本地继承环境当作统一发布口径。
- **challenge reexec 入口字段引用**：若引用 `summary.txt` 中的 challenge reexec 入口相关字段，必须原样保留 `replay_env_trnm_challenge_reexec_entry=` 与 `challenge_reexec_entry=`；若本轮未解析到入口，也必须原样保留 `<entry_not_found>`，不要省略、改写或润色成“待补”。
- **RC manifest 引用边界**：若引用 `trillionnium-rust/scripts/release_rc.sh` 生成的 `manifest.txt`，必须连同 `truth_source=`、`historical_evidence_only=true`、`evidence_scope=` 一起引用；不得只摘录产物或 PASS 日志并把 RC 产物表述成“当前 release-ready 证明”。
- **跨产物身份一致性**：若同时引用 `summary.txt` 与 `manifest.txt`，必须核对 `git_branch=`、`git_head=`、`git_head_state=`、`git_worktree_path=`、`git_worktree_branch_ref=`、`git_expected_worktree_branch_ref=`、`git_worktree_branch_ref_match=` 一致；其中 `git_worktree_branch_ref_match` 必须为 `true`，不能把 `false` / `unknown` 当作可放行状态。任一 artifact path 未解析到，或这些字段跨产物漂移，一律按 **evidence-incomplete** 处理，不得用“应该没问题”放行。
- **最新产物不自动等于当前 lane**：即使 `ls -dt run/health/evidence-*` 或 `ls -dt release/rc-*` 能解析出“最新”目录，也只能说明当前 checkout 下存在最近一次产物；仍必须把 artifact 内的 `git_worktree_path=`、`git_worktree_branch_ref=` 与票据/任务指定的 worktree 与 branch 逐项比对。不要把“这是当前目录下最新产物”当成 lane 绑定证明。
- **优先使用 fail-closed helper**：做 handoff / 审计引用时，优先运行 `./trillionnium-rust/scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root <ticket-path> --expected-branch-ref <ticket-branch>`（在 `trillionnium-rust/` 下可写成 `./scripts/v2/extract_release_handoff_fields.sh --expected-worktree-root <ticket-path> --expected-branch-ref <ticket-branch>`）；其中 `--expected-branch-ref` 可传短分支名（如 `lane/foo`）或完整 ref（如 `refs/heads/lane/foo`）。这样能让字段抽取与 lane 绑定校验一起 fail-closed；不要凭 shell scrollback 手抄字段，以免把缺失产物、错误 worktree，或 identity drift 误当成可发布证据。
- **helper 输出本身也要落成可引用产物**：运行 `extract_release_handoff_fields.sh` 时，优先把输出通过 `tee` 保存成 path-resolved transcript（例如 `trillionnium-rust/run/preflight/handoff-fields-<timestamp>.txt` 或同类审计路径），不要只把结果留在终端滚动里。后续 GO / NO-GO memo 应直接从这份已保存 transcript 或原始 artifact 引用 `summary_generated_at=`、`manifest_generated_at=`、`git_status_summary=`、`git_worktree_path=`、`git_worktree_branch_ref=`、`git_expected_worktree_branch_ref=`、`git_worktree_branch_ref_match=`、`rollback_command=`、`replay_command=`、`truth_source=`、`historical_evidence_only=`、`evidence_scope=`，而不是凭记忆转抄。
- **lane 绑定验证要用票据给定值，不要从当前 shell 反推**：进入 RC / handoff 流程前，若任务已指定 worktree/branch，先用票据中的绝对路径与 branch ref 跑 `./trillionnium-rust/scripts/v2/verify_lane_worktree.sh --expected-worktree-root <ticket-path> --expected-branch-ref <ticket-branch>`（或在 `trillionnium-rust/` 下执行 `./scripts/v2/verify_lane_worktree.sh ...`）；其中 `--expected-branch-ref` 同样接受短分支名或完整 ref。不要先从当前 shell 读取路径/分支再回填成 `EXPECTED_*`，否则只能证明“当前工作树自洽”，不能证明“当前工作树就是被指派的 lane”。
- **回滚命令**：每轮必须给出单行回滚命令（例如 `git revert <commit>` 或文档改动的 `git checkout -- <file>`）。
- **根因标签**：失败时使用统一标签（建议：`CI_FLAKE` / `ENV_DRIFT` / `DOC_DRIFT` / `MISSING_FIXTURE` / `NON_DETERMINISTIC_TEST`）。

建议在每轮提交信息或随附说明中使用固定字段：`gate`、`evidence`、`rollback`、`root_cause`，便于后续审计与自动汇总。

## 仍然 deferred / 未在本次文档修正中解决

1. 未重新执行整仓 release 级门禁，也未重新生成新的 closeout bundle。
2. 未对所有历史文档逐篇改写，只对最容易造成“当前已就绪”误解的入口文档做了降级说明。
3. 未在本次工作中改变代码或发布脚本行为；本次仅收口 truth-source 与文档口径。
