# bb026697：CodeQL 与 W1 work security 原始失败分诊

## 结论与范围

这两条 workflow 的红灯均有实际原因，保持 HOLD。此次只读审计没有修改源码、workflow、权限、资源、4 秒/depth 6 合同，也没有重跑 native 测试或再次 dispatch。

| 原 run | 原 job | 分类 | 直接原因 |
| --- | --- | --- | --- |
| [CodeQL export 42508015975](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015975) | 128814764789 | 精确来源上游分析缺失，exporter 等待到期 | 39 次成功 API 响应都没有 CodeQL checks 或 analyses；20 分钟内未形成可导出分析 |
| [W1 work security 42508015817](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015817) | 128814764330（head） | 原 Host 下真实业务确认目标失败 | 原测试 native exit 0，但 finite target 为 false，reader 拒绝 CONFIRMATION_TARGET；fresh 测试 native exit 101 |
| 同一 W1 run | 128814764420（prospective merge） | 独立来源 lane 的同类真实失败 | 保留合并提交身份，分别记录原测试与 fresh 测试的失败 |

W1 全 run 的 23 个 jobs 为 20 success、2 failure、1 skipped。此处只下载并审核两个失败 service lane 的原包；没有把其他成功 jobs 当作这两个 lane 的替代证据。

## 精确来源

- PR head：`bb026697a972521009bc133ae6ed2b653e18e931`。
- PR base：`7e044b65454f4c9ea505591727332acffb33e7e5`，分支 `fix/chain-p0-unified-qualification-20261108-99b5`。
- prospective merge：`4b55e3b3a01ad44f4da37a76298232e4a29d031a`。
- 两个测量 tree 均为 `18175756871bf341586fc37be1b17a00ef1dd099`；**tree 相同不把 merge 结果改记为 head 结果**。
- CI 原 source receipts 记录完整 23,515 个 tracked entries / 2,382,494,143 bytes，before/after 一致。此次原包审计比较了这些实际回执及 native manifest；并未声称外部独立托管证明或完整执行加载闭包。
- 源码解释来自完整、clean 的 bb checkout 的固定 git objects。六个相关文件的 git blob 和 SHA-256 在 [triage.json](triage.json) 的 `source_contract_files`。

## CodeQL：39 次成功空响应，不能改称权限拒绝

原 exporter 于 18:14:18.524484Z 开始，18:34:11.759191Z 结束，结果：

`CodeQL analyses/checks did not complete and stabilize before the deadline`

[原 result](selected-original/13629186603/analysis/result.json) 保留 `complete=false`、`analyses=[]`、`last_checks=[]`、`target_pr_gate_authenticated=false`、`target_pr_gate_verdict=null`。原 ZIP 包含 poll-001 到 poll-039 的全部响应；每次：

- `analyses-1.json` 是 `[]`；
- 精确 bb 与精确 4b55 的 `check-runs` 响应分别都是 `{"total_count":0,"check_runs":[]}`；
- selection 的 `ready=false`。

没有 403/401 权限错误记录；本次原因是没有形成可导出的精确分析输入。不能从空响应推断仓库的 Default Setup 配置或彻底断言某个分析引擎永久不存在。

源码触发边界解释了为什么不能期待当前本地 SARIF lane 自动填补：

- `.github/workflows/codeql-analysis-export.yml` 对全部 `pull_request` 启动，以既有只读 token 等待上游；`--wait-seconds 1200 --poll-seconds 30`。
- `.github/workflows/codeql-real-exact-source.yml` 的 PR base 只含 `main` 与 `fix/chain-six-axis-performance-20261103`，不包含本次堆叠 PR 的 base。
- 该 real lane 写的是独立保留的本地 SARIF，`upload: never`。它不等价于 exporter 严格读取的 Default Setup `CodeQL` / `github-advanced-security` check 与 API analyses。
- 因此此次不通过放宽 reader、延长等待、改变权限或将本地 SARIF 填作 API 分析来消除红灯。如何使所需分析在这个 PR base 产生，是另外的实际工作流/平台问题。

## W1：原资源内真实四秒目标失败

两个 lane 均真实完成 release build（exit 0），执行了原 selector 与 fresh selector，没有 compiler error、外层 process timeout、Host provision error 或旧来源 pin mismatch。原 Host 内前后记录都为：

| 项 | 原回读 |
| --- | --- |
| CPU | `cpu.max = 25000 100000`，quarter-core |
| CPU burst | `0` |
| Memory / swap | `2147483648` / `0` |
| pids | `256` |
| uid/gid | `1001/1001` |
| privileges | `CapBnd=0000000000000000`，`NoNewPrivs=1` |
| read errors / child Host errors / final Host errors | 空 |
| parent / boot / service cgroup | 各 lane before/after 一致 |

安装单元 SHA-256 是 `74eb36a63559bf8603c15ddd3753a1db143684a2cefd84cce5aff10a76bbd622`。两套 independently built retained ELF 各自 before/after 与原包实际字节一致，SHA-256 均为 `4942d95ef6b826c38ac5e680cf76e04655bbddb35c43ba48bb1d851cac6271cf`，11,601,384 bytes。

| 来源 / selector | baseline 确认延迟 | baseline 深度 | hostile 窗内业务确认 | hostile 结果 |
| --- | ---: | ---: | ---: | --- |
| bb / original | 3.483177149 s | 6 | 0 | PUBLIC_REQUEST_DEADLINE |
| bb / fresh | 3.400256343 s | 6 | 0 | PUBLIC_REQUEST_DEADLINE |
| 4b55 / original | 3.102359682 s | 6 | 0 | PUBLIC_REQUEST_DEADLINE |
| 4b55 / fresh | 3.096278267 s | 6 | 0 | PUBLIC_REQUEST_DEADLINE |

这是 original/fresh 各自的 4 秒双阶段 service 工作负载，不是 F0 的 30 秒阶段，也不是 1024-transfer 原三次完整 campaign。不要跨工作负载混用数字。

两种 selector 的 hostile phase 均保留 `client_confirmation_latency_ns=null`、`finite_business_target_met=false`、`full_native_state_equal=false`、`verification_errors=["PUBLIC_REQUEST_DEADLINE"]`。其 protocol/accounting invariants 仍为 true，并未把未完成独立重放的状态相等性冒充完成。

原 selector 的 cargo 测试成功仅表示所声明的 native invariants；实际业务指标单独是 false，runner 正确保留 `CONFIRMATION_TARGET`。fresh selector 在 `fresh_challenge.rs:244` 实际断言旧四秒/六深度目标，native exit 101，runner 记录 `FRESH_NATIVE_PROCESS_REQUIRED`。两个 original 和两个 fresh 结果都不能用编译成功或原测试 exit 0 覆盖。

合格 goodput 与完整延迟尾分布仍未成立，保留 null；没有把四个单次 baseline 延迟算成生产 p99，也没有把窗口内零确认当作总体容量定理。独立运营者、WAN、work hardness、生产启用均未由这些回执获得资格。

## 保留原件与完整性

| 原 artifact ID | ZIP | bytes | SHA-256 |
| --- | --- | ---: | --- |
| 13629186603 | [artifact-13629186603.zip](artifact-13629186603.zip) | 198,416 | `087095a9fe7703a089f5951cd17fde528e72f6db8b276f16dd89e2632b62fac5` |
| 13628771427 | [artifact-13628771427.zip](artifact-13628771427.zip) | 5,726,125 | `207f91a2bd632941b38e97dc2ba3543409c595330dfc06562aefdf8a941234a3` |
| 13628443294 | [artifact-13628443294.zip](artifact-13628443294.zip) | 5,756,162 | `a10c9bdebbd5432601e3899aa3f04c64f29d6556de43bf18ccb37f6088d61261` |

三个 ZIP 均逐字节匹配 GitHub artifact digest 和 size。CodeQL root manifest 的 203 个文件及 nested manifest 的 199 个文件全部核对；两个 manifest 本身由原 ZIP digest 绑定。每个 W1 native manifest 的 26 个成员全部逐字节核对，包括原 report、SQLite、日志与 ELF；Host/source 原件由原 ZIP digest 保留。

只从 ZIP 取出了 40 个便于复核的小文件到 `selected-original/`。大型原 report、SQLite 和 ELF 留在原 ZIP，没有完整解包或重压缩。原 run/jobs/artifact metadata 和三个失败 job 的原解码日志同目录保留。Actions 30 天保留期不足以作为永久证据，因此这三个原 ZIP 应随本目录一次入库保留。

[audit_triage.py](audit_triage.py) 是只读原件审计脚本，不运行仓库程序或 native workload。[triage.json](triage.json) 是实际执行后的详细结果与原 report JSON 路径/哈希。审计脚本第一次把 nested manifest 自身误列为应在 root manifest 内，已明确保留为 [audit-attempt-1.json](audit-attempt-1.json) 的**审计器自身拒绝**；这不是原 CI 的新增失败，也没有改动原包。修正 manifest 覆盖规则后完成上述检查。

`42509669473-jobs-initial.json` 只是另一个仍在监测的 F0 workflow 的中间状态，不属于此处两个已完成失败 run 的 native 结果。F0 的最终证据继续独立保留。
