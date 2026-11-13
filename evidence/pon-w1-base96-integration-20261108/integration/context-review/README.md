# C7 CI 上下文最小路线只读审阅

建议先集成已审阅的固定 base96 为 C7，并保持现有 CI guard/context 不变。当前 PR 事件使用 base62，而实际 merge 的有序父提交为 base96、C6；现有拒绝符合源码身份边界。39 项相关失败应按 38 个 prospective-merge lane 与 1 个 CodeQL export 分列，retained-pressure-failure 是另一原因。

共享 guard 先要求事件 base/head 与实际 merge 的有序父提交完全相等，再重算 canonical merge tree 和读取全部受控源字节。CodeQL export 另行绑定事件及 live PR 身份，并检查相同的有序父提交。integration push resolver 则是单独的 push/main 快照协议，明确不能承接 PR 事件。

C7 形成后必须读取新事件的 candidate/base/GITHUB_SHA 与实际 merge parents/tree。若 base 未再漂移，应要求 [base96,C7]，再对新 C7 的精确 commit/tree 取得资格。新提交本身不保证平台事件缓存恢复一致；如果新事件仍提供 base62 而 merge 父提交使用 base96，应保留新证据并诊断上游，不应从被检查的 merge 自己提取 expected base、切换为浮动 branch tip 或放宽为祖先/相同树。

原失败与 business steps skipped 均保留。旧事件不应因新候选而被重新标记为通过。完整检查依据、来源 SHA、必要拒绝控制与读取范围见 [summary.json](summary.json)；[snapshot.original.json](snapshot.original.json) 是已保留时点的原 API/git 摘要，仍有运行中检查，不是最终 CI 总裁决。

本审阅未修改源码、未启动测试或重跑 CI。后续 C7 工作树整合和精确资格另行记账。

