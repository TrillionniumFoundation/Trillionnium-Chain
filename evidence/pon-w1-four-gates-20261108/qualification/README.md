# C5 精确源码资格与原始失败

实际被测源码为 [034aa74358e0a5fa33f33e83cb63669e9738da4b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/034aa74358e0a5fa33f33e83cb63669e9738da4b)，tree 为 8dd452c376452224602fb202940ae84fc1f84d2e。此目录是独立文档分支上的事后 attestation，不是被执行的源码提交；每个最终组件保留运行前后 clean-source 检查、实际 argv、clock、退出与 stdout/stderr 哈希。

## 已完成的本地实际资格

| 组件 | 满足预声明结果的命令 | 实际普通测试方法 |
| --- | ---: | --- |
| CI core | 19 | 518 Python；其中 mandatory W1 为 151，既有 staged observer 为 32 |
| Owner / M12 | 19 | 37 Rust 通过、0 失败；4 个 heavy 入口在普通套件中 ignored |
| 真实 receiver | 4 | 11 Python，实际运行新 C5 verifier，0 skip |
| Backend build / source probe | 7 | 构建、锁定图及实际运行时源码探针；没有完整生成样本 |
| Native winner / verifier | 10 | 2 + 2 Rust；未重跑历史 native 全 243 项 |

合计 59 条命令满足各自预声明结果：58 条 exit 0，1 条 source-only unknown-stage 探针在实际验证源码身份后按预期 exit 1。普通套件合计 529 Python + 41 Rust = 570 通过，4 个 ignored 单列。实际昂贵 timeout/refund/reorg 与独立 cold 各执行 1 个精确入口，见 [生命周期原件](../lifecycle-c5/README.md)，不把它们加入完整生成样本。

[聚合机器结果](summary.json) 与 [归档哈希清单](component-archives-final.json) 对应 final-ci-core、final-owner、final-receiver、final-backend、final-native 五份原始 manifest、逐文件清单及 tar.gz。归档保留实际日志；单个 manifest 及其 source-before/after 不被后来的文案改写。

## 构建与二进制身份

| 实际角色 | 字节数 | SHA256 |
| --- | ---: | --- |
| C5 owner test ELF | 468126952 | 41c2d70d80282414bef23a90f22130e5da26e1ac30c8fddc8c5aec6e9de54d24 |
| staged runner | 47794488 | 499b9e67297907cc5a2ab1062b17c57c60bb5a022240f27526451c1d9ff6ae91 |
| C5 native winner | 752472 | 753c8c3610dcf0687e2d54f19e5c5b307dd54683bedabc7fe3d39eed57ee4b03 |
| C5 verifier | 19332368 | 91bbf96300d9b6d34cbf36415febae33908b8589de3004801e2a9e136153b7bd |
| retained upstream r0vm 3.0.3 | 108764424 | 2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6 |
| retained guest | 375928 | 25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f |

Cargo 使用 locked/offline graph、Rust 1.95、规范绝对 RUSTC/RUSTDOC 路径，明确采用复制缓存，非独立 cleanroom build。guest 未重编。C5 runner 在同一实际 checkout 的 C4 阶段已经构建，C5 Cargo 如实报告缓存命中；实际运行时 source probe 验证 C5 commit/tree。Native winner 与 verifier 在 C5 的真实 build artifact 均为 fresh=false，native 字节恰与旧文件相同不替代构建来源记录。上游 r0vm 工具的 3.0.3 与 Cargo SDK 版本不能混淆。

最终 owner 的规范 compiler 路径解决了前轮 build 警告，但本次研究入口使用普通研究 Node opener；没有由此取得 NativeIoOwner 的全 I/O owner-domain 预算资格。CI-core 和 owner 原始 manifest 有一个继承但未使用的 retained_verifier_source_commit=C3 描述字段，这两个组件没有执行 verifier。实际 receiver 的独立 manifest、argv 和 native artifact 均指向新 C5 verifier。原始 manifest 逐字保留。

## 失败与修复按实际源码分开

- C4 CI 原件 overall=false：旧 PQ source pins 拒绝新字节；32 个 staged 控制中一个 200ms 启动窗口耗尽；真实 receiver 因旧 C3 ELF 路径不存在而在测试前失败、执行方法数 0。其他套件及 mandatory 151 保留各自实际结果。
- C5 更新 21 个既有 pin，注册 8 个新源及独立负控镜像；完整 pin 为 645，原资格仍 HOLD。Observer 只调整测试：真实子进程退出 0，经 WNOWAIT 保留，再延迟至预声明 deadline 之后由 wait4 观察。生产计时实现未变。
- C4 owner 19 条命令、37 Rust 通过及绝对 compiler 路径警告保留。C5 的独立重验及新 ELF 不改写该旧结果。
- 最初复制大型 owner cache 的原超时，以及只读续拷、backend wrapper/source-output 名称冲突和全部准备失败，保留其已有原件；没有把重试算作同一次成功。
- [首个新失败 operation](../failed-operation/README.md) 因旧 runner 的编译时 checkout 身份被严格拒绝。保留原操作与原 deadline，没有重派或冒充自然超时成功。
- [C3 业务 CI 原件](../ci-c3/README.md) 继续作为业务失败样本，本目录的开发资格不覆盖它们。

外部 driver/plan、cache-copy 记录以及 corrections-and-reviews 归档在此目录中供复核。初期组件索引与最终组件索引分开，前者不包含尚在运行的 CI core；最终索引补上其真实完成后的原件。所有 source guards、读取、缓存和打包动作均不计为 fresh proof generation。

## 独立只读复核

[普通测试及 ABBA 草案回核](c5-qualification-and-abba-readonly-audit.json) 对 104 份实际 stdout/stderr 验 bytes/SHA，重算 52 条 exit 0 命令中的 570 通过与 4 ignored；另 7 条 backend 命令在其原始 manifest 单列。该复核没有重跑测试。

[昂贵超时与重组窄审](adversarial-c5-timeout-review.json) 重算两层 typed evidence digest，核对自然超时到 owner 请求的严格顺序和同一原 Cancel；[一致性结果](adversarial-c5-timeout-consistency.json) 与 [原 durable job 读回](adversarial-c5-timeout-original-jobs.json) 保留实际依据。余额等式依赖精确 C5 的成功状态机断言，审阅本身未重新打开 Node；不是独立账户重执行或完整安全审计。
