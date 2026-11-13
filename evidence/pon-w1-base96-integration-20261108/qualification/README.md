# C7 精确源码资格：独立原件复核

本包绑定源码提交 `40a3a45d6b8afc5c4706c5235fec47634f4aabbe`、tree `4b25e3194a0682adff40bb476f2e7c0a395639fe`。这是冻结 C7 之后的精确源码资格，不把提交前的候选控制、C6 的旧结果或后续文档提交算进 C7 的测试分母。文档与归档是事后整理；运行源码身份始终是 C7。

独立审阅逐项重算原 manifest、plan／driver、每条实际命令的 stdout／stderr 字节数与 SHA256，解析原始 `OK`、Rust result 与具名测试终态，并核前后 source guard、实际 Cargo artifact 和来源链。七个组件共 **69 条实际命令、655 个普通方法 PASS、0 failure／error／skip，另有 owner 的 4 个 ignored 方法**。History 的 1 个 ignored 入口仅被列出，不增加普通 PASS 或 ignored 执行计数。

| 组件 | 实际命令 | 原始输出中的结果 | 范围 |
| --- | ---: | --- | --- |
| Core | 20 | Python 571 PASS | CI／source／corpus／仓库控制及 W1 既有命令块；含 History 控制 6、Host helper 控制 79 |
| Owner | 19 | Rust 37 PASS、4 ignored | M12、Node 短控制、legacy admission／reorg；重型入口未在该套普通方法中执行 |
| Receiver | 4 | Python 11 PASS、0 skip | C7 实际 verifier，保留的 11 月 5 日完整 v2 证明与 expected-artifacts；没有生成新证明 |
| Backend | 7 | 构建与 source probe 通过声明合同 | probe 打印实际 C7 source identity 后以预期 exit 1 拒绝未知 stage；没有启动 proof |
| Native | 10 | Rust 4 PASS | native winner example 2、verifier 2；没有重跑历史 243 套 |
| History local | 5 | release 编译成功、精确入口列出 1 个 | `--no-run` 后仅 `--exact --ignored --list`；0 方法 PASS，未执行 4105-block workload |
| Staged | 4 | Python 32 PASS、0 skip | 全部已知构建终态后的一次独立运行；原 argv 和原 fixture deadline 不变 |

普通方法分母由原始输出相加得到：Python `571 + 11 + 32 = 614`，Rust `37 + 4 = 41`，合计 655。69 条命令包含各组件的 preflight 和前后 source identity 检查；这些检查不是额外测试方法。backend 的预期 unknown-stage exit 1 与“命令失败”分开呈现，所有七个外层 qualification job 均为 exit 0、complete、durable。

## 构建与接收来源链

Owner 使用新建空 target。原 preparation 和 exec 前 launch binding 的字节、SHA、device／inode、0 entries 记录相匹配；实际 Cargo JSON 唯一 artifact 指向 C7 checkout。独立审核复查该原始 JSON 和全部 owner 命令输出，未再次读取 467,950,280 字节的 owner ELF：其 SHA256 来自明确标为“衍生提取”的独立 owner import 原件，不冒充资格驱动原本已写出的 artifact 文件。registry 与工具链复用，因此没有独立 cleanroom／可重现构建结论。

Backend 与 native 使用从已资格 C6 target 复制到独立新目录的缓存，`fresh_cargo_target=false`。原 copy 回执保留初始 inode 隔离、原目录未写和来源 qualification pin；构建后的实际 Cargo artifact、C7 源路径及二进制 SHA 在本审核再次核对。reflink 可以共享写时复制存储，不能称为完全独立缓存。实际声明的资格构建预算是 2400 秒；缓存复制的外层预算是 1800 秒。二者均不是 operation 的 120 秒 deadline。

Receiver 的 launch binding 连到这份 C7 native manifest、20 个实际 native stdout／stderr 原件和 verifier SHA `93a1721d829846da2a4ab01f41238cf5d95351ce002556cc0840d009629e4219`。审核再次重算这 20 个输出与实际 verifier，不以“绑定成功”的布尔值代替原件。Receiver 使用历史完整证明执行 11 个真实控制；这不是两份 11 月 7 日 fresh proof 的重新生成，也不是中奖 W1 的 Node admission。

History local 复用已完成的 C7 owner target，release artifact 的源路径、Cargo profile、实际 ELF 和精确 list argv 单独核对。被列出的 ignored 入口没有执行真实 4105-block body；这个证据范围不能被写成完整 History workload PASS。

## 审核自身的失败与续行

第一次独立审计已封好 core／owner／receiver 后，在 backend 成品 ELF 的 `nlink==1` 自加断言停止。该断言错误地把“初始缓存复制的 inode 隔离”延伸成“Cargo 构建后的成品必须只有一个硬链接”。这是审核器的限制错误，没有任何资格命令或测试因此失败。

`audit-history/` 保留原 exit 1、stderr、已执行驱动及后续只读续行。续行只审 backend／native 剩余原件，要求 regular file、同 fd 读取期间稳定、实际字节与 SHA 匹配，并记录当前链接数；原 cache-copy 隔离条件完整保留。没有重跑测试，也没有用随后通过的样本覆盖原失败。History／staged 在自己的 qualification 终态后另行审阅。

## 归档与资格边界

各组件子目录的 `raw-output-index.json` 显示原路径、字节数与 SHA256，并映射到 `raw-logs.tar.gz` 的唯一成员。归档已逐成员读回；没有复制 ELF、SQLite、state 目录、进程环境转储或凭据。顶层 `manifest.json` 明列全部发布成员，包含组件内部 manifest 与审核历史。它声明的是磁盘／归档核验；最终 Git index 和 published commit 的完整性由发布者按明列成员另行读回，不能只以工作树文件数量宣称已发布。

本包的审核与归档没有执行新测试、构建或 operation。本轮 C7 昂贵操作启动保留为 **launch-Unknown**，没有取得 heavy／cold 实际执行证据；不能据此报 120 秒运行、timeout、退款、reorg 或 cold 完成，也不能从末次未观察到进程／文件推断从未执行。C5／C6 已有的真实路径保留各自原 source 与 operation，不转记为 C7。655 个普通控制不能补足这一缺口。

这里也没有新完整 proof、正向 provider 付款、完整资源计费、原业务预算通过、广域延迟收益、中奖 W1 Node admission 或完整密码学／协议安全资格。历史 ABBA 80 行没有因此变成 C7 完整生成对照；四个工程门仍为 HOLD。

新的 PR event／base／candidate／prospective-merge tuple 和 hosted CI 必须按实际身份另行核对。观察到后续 base91 的静态 clean tree，不会把本包的 C7 源码和 ELF 身份改成新树，也不构成新的执行资格。
