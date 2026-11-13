# C5 GitHub CI：当前源码的实际失败与分层读回

本目录记录 PR #782 head 034aa74358e0a5fa33f33e83cb63669e9738da4b 推送后自动执行的 CI。它与 [C3 历史失败](../ci-c3/README.md) 分开，也不属于 [570 项本地普通测试](../qualification/README.md) 的通过计数。

## 快照范围

[05:20 UTC 原始快照](checks-snapshot-01.json) 的 104 checks 为 48 SUCCESS、8 FAILURE、45 IN_PROGRESS、3 SKIPPED。该时点不是全局终态，不对其余运行中或后来出现的结果推断根因。

本次只读取该快照中 8 个已完成失败 job 的 metadata、原日志和它们上传的相关 artifact。没有重跑工作流，没有更换源码、预算或期限。下载 ZIP 的实际 SHA 与原上传日志分别核对；公开包保留允许公开的日志、报告和哈希记录，原 ZIP 留在外部工作目录，SQLite、完整 state、环境及凭据不进入本目录。

## 已核清的 8 个失败 job

| job 范围 | 真实失败层 | 已完成事实与限制 |
| --- | --- | --- |
| retained-pressure-failure，1 个 | 历史 artifact 获取 | 原 artifact 查询 Found 0、所需 ID 未找到，后续诊断 step skipped。不能计作新的压力执行失败，也不推定历史内容本身有问题。 |
| original native campaign，1 个 job 内 3 次 campaign | 原 30 秒业务阶段 | 三次均实际执行、exit101；共 9 个阶段 finite=false，均记录 PUBLIC_REQUEST_DEADLINE。每次 baseline 仅 round0 获得六层确认、round1 失败；每个压力阶段 24 attackers ready、0 个成功确认。无 phase_startup_errors，report_validation_failure=null。 |
| W1 fresh challenge service，head / prospective merge 两个 job | 原 4 秒／6 层确认条件 | original 与 fresh 的 4 个无攻击 baseline 各确认 1 笔；4 个 16-worker pressure 均 0 笔及时确认，finite=false。original native test exit0 不能覆盖业务失败；fresh native test 实际 exit101，在业务断言处失败。 |
| protocol-contract / prospective merge / cross-arch x64 / cross-arch arm64，4 个 job | CONFIRMATION_TARGET | 每个的 5 个具名 native test 均 exit0、无 timeout，service 与 sustained report passed；confirmation report failed。原 4 秒 baseline 1/1、pressure 0/1。head、x64、arm64 的 pressure 错误为 PUBLIC_REQUEST_DEADLINE；prospective merge 的 verification_errors 是空数组，不为它补造同一错误码。 |

[业务 job 的原件与精确结论](business/README.md) 和 [protocol / cross-arch 的原件与精确结论](protocol/README.md) 分别提供每个 job 的实际源码身份、失败 step、完整相关 stdout/result 和逐文件 SHA 清单。

W1 fresh 的错误细节也分开保留：original pressure 的最后 replay 是 PUBLIC_REQUEST_DEADLINE；fresh pressure 的 verification_errors 为空、最后 replay accepted=true，但依然没有在窗口内完成六层确认。head / merge 实际构建并提交的唯一 fresh challenge 分别为 213 / 210。accepted 不构成及时确认，也不能将这两种失败写成同一个 replay 错误。

## 源码与资格边界

八个 job 的 GitHub head 均为 C5。prospective-merge 测试记录的是各自真实 merge commit（991168a…），其 tree 与 C5 相同；不能把 GitHub head 字段当作实际 tested_commit。对应 source guards、构建及 host 前置条件已分别保留。protocol/cross-arch 的 native no-run 构建成功，实际 host setup 无 error，失败发生于后续服务控制。

这些结果支持“当前源码下原业务判据仍失败”。没有仅凭失败或与 C3 相似就断言 C5 引入了回归，也没有仅凭前置通过排除所有回归。当前原生服务和维护块也不构成两份旧完整 zkVM 证明所对应中奖 W1 的 Node admission。

远端 CI 未被宣布全绿，原业务资源资格仍 HOLD。新的昂贵 timeout/refund/reorg/cold 成功与此处的业务失败同时保留，各自维持原操作、原 deadline 和原判断条件。
