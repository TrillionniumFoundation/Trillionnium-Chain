# W1 C3 精确源码资格与未通过的工程门

本目录引用固定的被测候选 **`abab79dac0cb89eb2753d3f579119ac135650eb5`**，tree **`194808f4a0db5d642aa746beb251ca9e9532cebb`**。C3 的两个父提交是已发布的 C2 `cc4dd8bdd89309c635831db30b508af2f89419d7` 和现有 integration 的 `cb314bb4656e5da4844325cd83994ab4764fe8e9`。本目录追加在独立文档分支上，资格仅适用于 C3；包含本目录的文档提交不冒充被测试的运行源码。

## 本轮实际验证

| 组件 | 成功命令 | 实际通过结果 | 范围 |
| --- | ---: | ---: | --- |
| 后端 | 13 | 22 | 分段、递归、retained guest 与原锁文件 |
| Native / verifier / receiver | 21 | 252 | 243 个 native 名单、2 个 verifier、7 个 receiver 控制 |
| Owner / M12 / retained admission 与 reorg | 16 | 31 | async Node 15、M12 10、admission 1、reorg 5；另 3 个 heavy 入口 ignored |
| 本地选择性 CI | 19 | 471 | 其中 mandatory 104，原零 skip 守卫通过 |
| 冻结清单 | 12 | 0 | 3,057 项，双父提交和完整 tree composition |
| 聚合 | 4 | 0 | 原件、终态、二进制及源码前后核对 |
| 合计 | 85 | 776 | 测试结果数与辅助观察命令分别计算 |

四个组件均使用原唯一 job 取得真实 succeeded / exit 0、完整且持久的输出。owner 新增的 1 + 5 项按精确测试名核验，未混入 15 项 async Node 的计数。C3 的五组源码检查绑定固定候选的原始 source report；全树报告覆盖 15,332 个 tracked entries、1,672,127,995 字节。末端聚合已完成同一源码身份及原件的核对，源码前后报告的 SHA256 均为 `f64801ce2a5fd2e3e0814c4b68e5f7fdd7b740dd72aa90984eff69dcb5a1ba5f`。

末端聚合 attempt01 的首次 sourceguard 在原 180 秒时限内未完成并超时，未形成 qualification。后续两次有界 Git status 观察各在 15 秒超时，随后同一 status 命令实际以 0.213262 秒、exit 0 完成；原因仍未确定，不能归因于环境或 CPU。独立 attempt02 保持原环境、资源与时限，只增加开始／结束、实际资源观察和 trace 日志，四条资格命令均成功。原失败和诊断保留，不计入成功命令数；本轮合计为 **69 条组件命令 + 12 条冻结清单命令 + 4 条聚合命令 = 85 条**。

构建使用从已资格 C2 缓存复制的独立 target，并检查没有与原 target 共享普通文件 inode。原 Cargo 命令、locked graph、严格 Clippy、格式检查和实际测试均执行；Cargo 的 fresh/rebuilt 字段保留其真实含义。guest 使用已绑定的 retained v2 字节，没有重新编译；本轮没有重新生成完整 proof，不构成独立 cleanroom build。

本轮最初读取旧 C1 cache 失败，旧 C1/C1b owner target 的有界读回也显示原路径不存在。因此，本轮对它们当前二进制保全的结论为 UNKNOWN，历史资格文件仍保持原 SHA；没有重建旧路径或把新的 C2 cache 冒称旧 C1 原件。末端聚合已实际前后读取可用的 C2 五角色原件，五份 pin 均保持不变。失败的 cache 准备、owner 安装、map01 与末端聚合 attempt01 均单独保留，未计入成功命令数。

## 合并与证据保全

C3 保留上游完整 Legacy root admission arithmetic、retained admission/reorg 控制和本分支的 async W1 owner 接线。两个真实冲突位于 workflow 与 cross-branch corpus，按合并后的真实 store blob 绑定解决；完整 tree 与审阅组合一致。

初次普通 merge 的网络取回过程被正常取消，原 cancelled 终态保留。随后从已验证为同一仓库、固定上游提交的本地 cache 仅读取所缺的 1,279 个 Git objects，以标准 `pack-objects` / `index-pack --strict` 完成传递；来源 cache 未修改。283,683,189 字节的临时 pack 仅保留身份和校验结果，不收入公开归档。

提交前全量 whitespace check 的 5,479 条诊断全部来自 364 个上游原始证据文件，逐个 blob 与固定上游相同。保留了原检查 exit 2，原日志未改；本次 8 个非 evidence 路径的 whitespace check 为 0。

首轮 map 错把旧 709 项冻结子集视为覆盖全部 7 个修改路径。实际唯一缺项是已 tracked 的 `STATE_RECOVERY.md`；修正后显式核验 `old709 ∪ modified7 ∪ added2347 = 3057`。这是冻结子集的覆盖修正，旧 C2 的完整 source guard 不因此失效。首轮失败与新 map02 成功分别保留。

[reconciliation/archive-readback.json](reconciliation/archive-readback.json)确认支持包 194 个成员全部读回、共 11,402,211 解压字节；[reconciliation/PUBLIC-ALLOWLIST.json](reconciliation/PUBLIC-ALLOWLIST.json)列出完整选定原件。[reconciliation/reconciliation-raw.tar.gz](reconciliation/reconciliation-raw.tar.gz)的 SHA256 为 `00a7c8d8d52b584d8df29a83ecbc5b5bd3c28c1d7bcf3125035be8c90af07c3b`。

## GitHub 的负面结果仍保留

[早期 C2 读回](github-C2-readback/README.md)保存原业务压力失败及历史 artifact 不可取得的证据。x64 fresh-service head 在原四秒窗口内未达到确认目标，压力路径的一页返回时刻为 4.085282455 秒，被原 deadline 拒绝；ARM64 cost 的压力目标也未达成。原历史 artifact 的实际读回是 404，原 run 的 artifact 列表为空；不能据此断言是过期、删除或其他特定原因，也不能拿新实验冒充原件。

[后续 C2 读回](github-C2-late-readback/README.md)记录其后 104 项检查中的 82 SUCCESS、3 SKIPPED、16 FAILURE，另 3 项仍运行。这不是全局终态，也不是 C3 的远端结果。新增读取 9 个失败 job 的元数据和原日志，未重跑 workflow。

CodeQL export 失败的原文原因是分析与检查未在原截止时间前完成并稳定；它不等于漏洞发现。四个 history job 的 build preparation 通过，但原 controller 最终 passed=false / systemd_run_exit=1，不能把步骤名中的 4,105 块和 paid full sync 当作完成结果。其内层 artifact，以及三组 service-model 和 x64 cost 的内层失败原因，仍有未独立读取的部分。后续控制步骤中的 panic 没有被用于解释更早的失败。

本地 C3 的选择性验证成功，不替代 GitHub 完整矩阵，不将这些业务或历史证据门改成绿色。当前远端状态以 [PR #782](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/782) 的实际 head 为准。

## 四道工程门的实际边界

| 工程门 | 已有真实证据 | 仍未闭合 |
| --- | --- | --- |
| 实际 winner / receiver | 原生中奖、同一声明及各原实验预声明的研究期限；两份完整证明、本地与 ROG 独立严格接收；真实昂贵取消及 cold 读回 | 部署 WAN、中奖区块 Node admission、完整历史进程树 wait/reap 和资源计费；研究期限内完成不构成原业务预算通过 |
| 完整后端资源实验 | 同一固定输入下每方案各 1 次 fresh pipeline，各 43 segment / 43 lift / 42 join，顺序对照已有终态；共同 Rayon=2 的 ABBA 80 行完成，零新 generation | 每方案仅 1 份生成样本，无总体尾延迟；原生成配置与 owner 路径差异保留，原业务预算未通过 |
| 真实异步资金与操作链 | 昂贵完整生成已接 NativeTask Reserve 与 M12 Prepare/Intent/BindJob；另一个新 operation 的实际取消、一次本金退款和 cold 不重派已观察 | A 原完整生成操作与 C1b 新取消操作的 M12 均 Pending，C1b 原 cap 保留；昂贵 timeout/reorg 全路径、完整资源结算及正向一次性 provider 付款仍未闭合 |
| 部署收益与安全资格 | 保留完整 v2 独立 expected-artifacts 绑定，区分实现、成本和安全条件 | 新 ABBA 内层耗时中位数之比（proof/native，ratio of medians）约 13.06 / 13.43，payload 大小之比约 5.19；验证/传输部署收益和完整安全资格未建立，原业务预算未通过 |

四道工程门均保持 **HOLD**。各原实验预声明的研究期限与原 **4 秒 / 0.25 CPU / 2 GiB** 业务门分开判断；完整生成或接收在研究期限内完成，不构成该业务门通过。已实际失败的预算观测按其样本范围保留，尚未观测或未完成资格的部分继续记为 UNKNOWN 或未建立。

实验与源码的对应关系如下，原进程身份和观测均保持不变：

- **A `d3037ca5dfb6f301757c159b7888dca9b0317be0`**：两份完整生成、共同 Rayon=2 的 ABBA、原 4 秒窄探测及 ROG 接收观测。
- **C1 `cb557c5e59b00ba7c6b1d40f78fbe51031a26f11`**：原请求容量超限导致的 pre-dispatch 失败。
- **C1b `0f18f93f2d35b62c6ca6d63faf4f336d55cbf4bf`**：新 operation 的实际昂贵生成启动后取消、本金返还及 cold 不重派读回。
- **C3 `abab79dac0cb89eb2753d3f579119ac135650eb5`**：本轮源码、构建及保留控制资格检查，没有重新执行或重新归属上述历史实验；末端聚合资格已在固定 C3 上形成。

两份完整生成不是 C3 新执行。原生成配置的 worker/Rayon 和 owner 路径差异按原记录保留；共同 Rayon=2 的 ABBA 只统一其验证成本实验条件，80 行均不生成新证明，也不使原生成试验成为相同调度配置。这里的 ratio of medians 不是逐行比值的中位数，也不是资源计费比。ROG 返回包时间包含调度、传输和取回，不等于纯 WAN 延迟。

退款本金 1,000 与取消交易账户净增 709、Reserve+Cancel 总净变 −710 分开记录；费用相关残差没有被当作 provider 付款或资源 credit。NativeTask 取消与本金退款不等于 M12 结算，两项 M12 的 Pending 状态继续保留。GPU usage 仍 UNKNOWN，provider 付款为 0 的结论限于所审操作与交易。

[完整运行证据](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc4dd8bdd89309c635831db30b508af2f89419d7/evidence/pon-w1-fresh-runtime-20261107/README.md)与[机器可读实验结论](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc4dd8bdd89309c635831db30b508af2f89419d7/evidence/pon-w1-fresh-runtime-20261107/summary.json)保持原样。Kaggle CUDA 探针成功，后续 build-only 请求被正常 guard 拒绝；Colab 绑定/释放冲突及后续只读状态保留，没有据此声明成功释放或 GPU W1 资格。

## 资格文件

归档仅对明确列出的选定原件声明闭合。另一次本地历史工具文本导出对 24 个会话存储键均未取得记录，实际导出数为 0，没有重建返回文本；缺失清单位于归档内 `transport-originals/historical-agent-tool-text-export.json`。七份原远端终态文件、首次聚合的实际失败终态、命令日志与三轮诊断报告仍按其实际文件保留。

- [qualification.json](qualification.json)：C3 固定源码、逐命令日志、测试计数、原进程终态与二进制身份；SHA256 `2fbd82253b5610cf08afeaa3dfb6e36cbb2d183f8b6c5b564baba655e365d99f`。
- [qualification-raw.tar.gz](qualification-raw.tar.gz)及[成员索引](qualification-raw-index.json)：688 个原件、50478108 解压字节；归档 SHA256 `6a79e0f996ea18fe37eb606863c1b1de202539f7488dde7f26ddca1e331905e2`。
- [archive-readback.json](archive-readback.json)、[gate-job-statuses.json](gate-job-statuses.json)与[publication-receipt.json](publication-receipt.json)：真实封存终态与最终 pin。
- [artifact-inventory.json](artifact-inventory.json)：本目录其余公开文件的逐文件哈希，清单自身不递归包含自己。
- [原 C2 资格](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/583589d322bca9bad29c8367551bdcbe23e4a562/evidence/pon-w1-publication-qualification-20261107/README.md)：保留原 80 条命令 / 770 项结果，不改写成 C3 的新验证。

完整密码学、递归/AIR、PQ/QROM、语义、DA、模型效用和其余原有安全条件继续 HOLD。本记录没有赋予部署、共识激活或付款资格。
