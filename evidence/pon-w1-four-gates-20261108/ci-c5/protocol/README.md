# C5 四个已完成 protocol／cross-arch job 的原件回读

本目录保留 GitHub run **42449729551** 的四个已完成失败 job、单 job 日志和其上传 artifact 中明确允许公开的原始日志与报告。四处当前内层失败均为 **CONFIRMATION_TARGET**：原 **4 s** 窗口内，baseline 确认 **1/1**，pressure 确认 **0/1**。原业务目标继续失败，资格保持 **HOLD_NO_GO**。

## 具体失败

| Job | Job ID | GitHub 失败步骤 | Baseline 确认 | Pressure 确认 | Pressure verification_errors |
| --- | --- | --- | --- | --- | --- |
| protocol-contract | 128636161832 | Run actual protocol-contract checks | 1/1 | 0/1 | ["PUBLIC_REQUEST_DEADLINE"] |
| prospective-merge (protocol-contract) | 128636161885 | Execute the same lane on the prospective merge | 1/1 | 0/1 | [] |
| cross-arch-cost (x64) | 128636161945 | Execute exact native from-zero service controls | 1/1 | 0/1 | ["PUBLIC_REQUEST_DEADLINE"] |
| cross-arch-cost (arm64) | 128636161957 | Execute exact native from-zero service controls | 1/1 | 0/1 | ["PUBLIC_REQUEST_DEADLINE"] |

每个 job 的五个具名 Rust 测试进程均返回 **exit 0**，无进程 timeout；source_recompiled=true、format_passed=true、all_named_tests_passed=true、native_execution_completed=true。随后 service_report 与 sustained_report 验收通过，confirmation_report 验收失败；各内层 manifest 的 failures 均仅含 CONFIRMATION_TARGET。原件 execution_finished=false 表示包含报告验收的顺序未成功走完，不能解读为原生子进程仍在运行。

head protocol、x64、arm64 的压力报告记录 PUBLIC_REQUEST_DEADLINE；prospective merge 的该列表为空，同样记录压力确认 0/1 与业务目标失败。此处保留差异，不为合并候选补造 deadline 错误码。

四份保留记录中的源码身份、构建与 host controller 前置检查均已完成，内层实际阻塞是原业务确认目标。x64 和 arm64 在此失败之前的五个 native 成本步骤均在 GitHub metadata 中标记成功。当前证据没有证明新的代码回归，也不能据此排除所有可能的回归。

## 身份与范围

GitHub workflow 为 trnm-required-baseline，事件 pull_request，run attempt 1。四个 job 的 GitHub head 均为 C5 **034aa74358e0a5fa33f33e83cb63669e9738da4b**。head、x64、arm64 实际测试该提交；prospective merge 实际测试 **991168a783c3bf82e04f978091adbdc740998c47**。四者实际 tree 均为 **8dd452c376452224602fb202940ae84fc1f84d2e**。各原生 manifest 的 before／after 源身份完全一致；job 中独立的源身份检查及事后检查均成功。

这是对当前 C5 记录的事后只读诊断，没有用旧 C3 的失败来替代本次原件。没有重跑 CI、执行新测试、改动 source、延长 deadline 或生成新完整证明。下载 run metadata 时整体 run 仍为 in_progress；这里只报告这四个已完成 job，不宣称其他 job 或整个 run 的最终结论。

五个名称在四个 job 中各执行一次，形成 20 次原生进程成功返回；这不是 20 个新增独立测试，不改写另行公布的本地资格分母。原生测试返回成功不能替代业务报告验收，也不能证明此后 CI 命令已执行。这些有限本地服务报告不能授予广域网、完整 zkVM 生成、总体尾延迟、中奖 W1 的 Node admission 或部署资格。

## 原件与可复核性

- run-metadata.raw、各 job 的 job-metadata.raw 和 job-log.raw 是实际 gh api 返回的原始字节。
- retrieval.json 与 artifact-retrieval.json 保留具体 API argv、抓取起止、退出码、stdout／stderr 字节数及 SHA256。本次四个 artifact 的 metadata 与 ZIP 共 8 次请求全部 exit 0。
- 四个原始 ZIP 的 SHA256 均逐个匹配相应 job 上传步骤打印的 digest。原始 ZIP 及其完整 member 索引放在 Git 之外的 /tmp/chain-w1-c5-protocol-original-artifacts-ec265b/；未加入公开包。
- 各 retained-evidence.tar.gz 只打包明确 allowlist 的原字节：native manifest、三个完整 report、五项测试及构建／格式控制的 stdout／stderr／process、必要 host controller 记录与 source 身份。SQLite、可执行二进制、完整 state 目录与环境文件均未打入公开包。
- retained-member-manifest.json 给出每个公开 member 的大小与 SHA256。publication-disposition.json 绑定原始下载 ZIP、外部保留位置及公开归档，明确公开子集与原完整 artifact 的区别。
- parsed-native-diagnostic.json 是便于阅读的字段投影；完整原始报告在公开 allowlist 归档内。summary.json 保留逐 job 原值、错误差异和诊断边界。
- 根 manifest.json 绑定本目录除它自身之外的每个文件。所有公开单文件均小于 25 MiB。

[原始 run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42449729551)
