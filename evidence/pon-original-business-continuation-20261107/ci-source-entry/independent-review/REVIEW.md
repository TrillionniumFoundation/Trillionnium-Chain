# Integration push source — independent review

结论：在以下冻结字节上完成只读源码、工作流与本地反例审查，未发现剩余阻断问题。此结论允许把真实 push 作为明确独立的来源入口；它不是原业务矩阵已经执行或通过的结论，也不是 GitHub 生成的 PR merge 身份。

比较基线为 native commit `9ce78655b574a638c54a0ee9c88d58ffdec74df7`。审查未编辑被审文件、提交、推送、dispatch 或修改 GitHub 环境来运行原业务。

## 冻结字节与独立控制

| 文件 | SHA-256 |
|---|---|
| `scripts/ci/integration_push_source.py` | `d72d6106fa4bad0f82d88d2c98b06f5cad0c8823e98a7dbda72d4977d0e610d3` |
| `scripts/ci/test_integration_push_source.py` | `f2ce1dcb585bed2f2420bfa29e6673041c14f88cb735b969e42641577264e3b4` |
| `.github/workflows/pon-priority-acceptance.yml` | `6a7eeb14bc2fe1a005d0ee7403e1c6d2e5ba41e941c51892baf35002ecdd62fb` |
| `.github/workflows/pon-w1-work-security.yml` | `739854d721f5be0f2055bf211a9ebf929b64e8a3a5047a777fea4ab4166b3490` |
| `scripts/ci/check_ci_contract.py` | `8702d589d757625d886caded0757907b1a90e6c914652152cab86ea6ee44d5f7` |
| 原 `scripts/ci/verify_ci_source.py` | `0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946` |

preflight PASS；独立运行 `test_integration_push_source.py` 为 13/13，原 `test_ci_source_integrity.py` 为 43/43，完整 `check_ci_contract.py` exit 0。上述六文件在执行前后 hash 一致。完整 argv、退出码和日志 hash 见 `controls.json`，不把合成 Git fixture 的成功列为 hosted 事件验收。

## 来源与对象检查

1. 入口只增加现有集成分支的 push，保留原 pull_request 定义。helper 同时检查 event name、repository、真实 ref、GitHub SHA、payload after/head_commit.id，以及 run ID/attempt；创建、删除、forced push 与零 before 被拒绝。payload 摘要是 canonical JSON 摘要。
2. Resolver 先用原 verifier 完整核验 H，再从固定 GitHub HTTPS 仓库获取 main 的 B。B 是 resolver 实际运行时观察到的 main，不是 push 创建时的 main。随后完整复查 H 的身份与 tracked 字节未改变。
3. 新 merge 在无全局配置、无外部 driver 的临时 bare 中真实执行 merge-tree，固定 commit metadata 并按 B、H 顺序创建双亲 M；导入实际 commit/tree/blob 闭包后删除临时目录。独立原 `_canonical_merge_tree` 与最终原 verifier 再核对合并关系。新生成的 tree/blob 没有被误当作已经存在于 worker object store。
4. Worker 绑定 resolver 的 context 摘要、同一真实 event/run/attempt 与独立 EXPECTED_H/B/M。它仅获取已冻结的 B 对象，重建并要求相同 M；不重新读取 main。head 和 prospective-merge 都经过原严格 verifier；冲突没有人工解冲突或静默回退。
5. 未修改 GITHUB_EVENT_NAME、GITHUB_SHA 或事件文件。所有来源仍是实际 push；materialization receipt 明示 `is_github_pr_merge=false`。

## 原工作流保存范围

用独立 YAML 树比较器逐项对照基线；结果见 `workflow-preservation.json`。54 段原 run 脚本、原 step 条件和顺序、runner、timeout、fail-fast、业务/Host 命令、artifact 路径/保留天数以及旧失败 artifact job 均保留。

| 原 job | 展开组合 |
|---|---:|
| priority：2 runner × 2 source × 3 campaign | 12 |
| W1 false trace：2 arch × 2 source | 4 |
| W1 legal strategy：2 version × 2 arch × 2 source | 8 |
| W1 legal factorial：2 arch × 2 source | 4 |
| W1 fresh challenge：2 source | 2 |
| W1 rank/batch：2 arch × 2 source | 4 |
| 合计原 native lanes | 34 |

明确审查的新增/替换仅为 resolver、push-only materialize/回执保留步骤、frozen source 环境与 checkout 表达式、priority artifact 名称中使用 EXPECTED_HEAD，以及 W1 concurrency 的 PR-number-or-real-ref 回退。原 PR 的名称值/并发组保持相同，cancel-in-progress=false 保留。

原 PR 时 resolver skipped；native job 使用显式 `!cancelled()` status 函数并允许 pull_request 分支，避免默认 success 条件因 skipped dependency 而将整个原矩阵一起跳过。GitHub 官方文档明确 status 函数会覆盖默认 success，并列出 !cancelled() 作为可取消的继续条件。这里的判断是对定义与官方语义的审查；调度是否实际发生仍须真实 Actions 记录确认。

- https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions
- https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs#defining-prerequisite-jobs

## 失败回执修正

审查时指出：materialize 中途拒绝时，仅保留 generic error 不能直接重建该 lane 收到的 context。实现方现已在调用前保留有界原/解析后 attempted context、摘要、source kind、独立 EXPECTED_H/B/M，以及白名单 event/repository/ref/sha/run/attempt/job 字段。它们明确是 attempted/unverified；成功路径和任何 guard 未放宽。

新增 CLI 负例故意使 EXPECTED_BASE 不符，实际子进程非零退出，失败 JSON 为 completed=false，保留所收 context 和独立工作流身份，且没有 verified source。13 项最终控制包含该负例。实现方保留了其第一次测试 fixture 的失败日志；本审查记录也保留初始 YAML 比较器对两处合法表达式变化的拒绝，不冒称第一次检查即通过。

## 发布后仍需确认的事实

- 真实集成分支新 push 触发两个 resolver；需逐 run/job/artifact 核对完整 34-lane 分母，不能仅凭 workflow 绿色或 skipped/neutral 状态判通过。
- 两份 workflow 各自只冻结一次 B/M。只有 H、B、M 一致，才能把它们合成同一完整矩阵；context digest 含不同 run ID，本就应不同。
- 失败后应 rerun whole workflow。failed-jobs-only 不能借用旧 attempt 的 resolver context；跨 attempt 绑定会拒绝。
- 所有原四秒/16-worker、4105 History、实际激活、状态完整性和 source-after 门槛仍由原程序判断。本审查没有 native 性能结论。
