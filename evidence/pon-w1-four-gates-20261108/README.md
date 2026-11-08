# W1 四个工程门：C5 实际超时、退款重组、冷恢复与精确资格

本轮已将昂贵生成的自然超时、失败终态、owner 撤销、本金退款、真实分支重组和独立进程冷恢复走通。新 operation 的派发状态为 Done，完整资源 cap 仍保留；provider 未付款。四个部署工程门继续 HOLD。

实际运行源码固定为 [C5 034aa74358e0a5fa33f33e83cb63669e9738da4b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/034aa74358e0a5fa33f33e83cb63669e9738da4b)，tree 8dd452c376452224602fb202940ae84fc1f84d2e，继承 C3 和 M12 topic a5ec1ba3。本页及新的资格/生命周期文件是独立文档分支的事后 attestation；没有把事后文档提交冒充为被运行源码。旧两份完整证明、各原实验 deadline、旧 operation 和失败原件保持原事实。

## 四门更新

| 工程门 | 本轮实际增量 | 尚未闭合 |
| --- | --- | --- |
| 实际 winner / receiver 采集 | 修复实际 verifier stdout 与 observer digest 未绑定、JSON 类型别名和最终输入 pin 缺口；11 项真实 receiver 控制用新 C5 verifier 通过。新增 subreaper 的有限真实进程回收控制。 | 中奖 W1 的合法 Node admission、部署 WAN、全部历史进程身份/回收及完整资源计费。 |
| 完整后端同资源实验 | 原 80 行 / 20 个 ABBA block 通过独立严格重审；保留同资源完整生成参数草案。 | 两方案仍各 n=1，配置差异与总体尾延迟未消除；新完整生成数 0。草案的冻结源码/ELF pins 仍为空，未绑定 C5、不可直接开跑。原业务预算未通过。 |
| 真实异步 owner 接线 | 新昂贵任务真实启动后自然到达唯一原 deadline，先写 Failure Unknown，再 owner 撤销及本金退款；实际 fork 移除/恢复同一原 Cancel；独立 cold 不重派。新操作 M12 Done。 | Done 是派发终态，资源消耗仍 null、全 cap 保留；正向 provider 付款与完整资源结算未建立。旧两个相关操作仍按原记录 Pending。 |
| 部署收益与安全资格 | 精确 C5 完成 570 项普通测试；证据攻击反例进入 mandatory CI；新增 CPU 隔离短探针和费用独立审计，C3 业务失败全部保留。 | 验证/传输部署收益、原业务资源条件、完整密码学及协议安全资格未建立。 |

## 1. 实际昂贵超时、资金和重组

[生命周期原件与允许公开的逐文件清单](lifecycle-c5/README.md) 对应新 operation 3c722d76b352db7450c53321368b305782f25612b9ed1fb806c49c5ec7fb5c77。研究限制是 8 CPU、8 GiB、120 秒原始 proof 期限；外层 240 秒只用于终止/退款闭合，不恢复证明资格或更新原 deadline。

| 实际阶段 | 已观察到的事实 |
| --- | --- |
| 昂贵启动 | 固定 r0vm ELF 的 prove-batch-0000 实际进程及 parent runner、PID birth、boot、child cgroup、CPU affinity 一致；启动观察早于原 deadline。 |
| 自然超时 | 唯一原 deadline 为 1191795668407846 ns。Target cause=original-deadline、sticky_cancel=false、真实 exit=-9；结束观察 1191796086929474 ns，比原 deadline 晚 0.418521628 秒。 |
| 失败入账 | Runtime/helper 与 Rust caller 的实际终态绑定原 job、request、statement、source、clock；Failure Unknown 先于 owner 撤销。consumed=null，全 cap 保留。 |
| 取消与本金 | 后续显式 owner veto 阻止再派发；原 NativeTask Cancel 退回本金 1000。该退款不构成 provider 付款或资源 credit。 |
| 实际重组 | 更长有效 fork 移除原 Cancel，canonical 状态回到 Reserved/1000、不能继续声称已退款。本地操作历史不回退。通过延长原 ancestry 恢复同一 wire、packet 和 inclusion，不另签退款交易。 |
| 独立冷恢复 | 全新进程复用同一 operation、statement、原 deadline 和原 target 终态：M12 Done、cap 保留、原 Cancel 仍 canonical；0 dispatch、0 target cancel、0 native transaction。 |

实际 heavy 入口 1 通过，123.23 秒含超时后的收尾；独立 cold 入口 1 通过，0.45 秒。两次父进程均 exit 0 且输出完整持久。target 的 late terminal 是超时观察，不是完整 proof 的完成时间；本轮新增完整 proof 为 0。当前 child cgroup 递归为空、worker 原 birth identity 已不存在，不证明所有历史后代曾被完整记录和 wait/reap；cold 也只核原终态与当前 worker，不增加历史全树资格。

[此前新 operation 的源码拒绝失败](failed-operation/README.md) 单独保留：旧 C3 runner 从编译时 checkout 查询出的真实源码与新计划不符，原操作没有重派或延长 deadline，M12 仍 Pending、全 cap 保留。后续成功试验使用新构建来源和全新 operation，未改写该失败。

## 2. 精确源码本地资格已经完成

[完整资格、缓存来源、二进制 pin 与原始日志](qualification/README.md) 固定 C5 前后 clean source：

| 组件 | 实际普通测试 |
| --- | ---: |
| CI / source / evidence | 518 Python |
| 实际 receiver | 11 Python |
| Owner / M12 / retained admission / retained reorg | 37 Rust |
| Native winner 与 verifier | 4 Rust |
| 合计 | 570 通过；普通套件中另有 4 个 heavy 入口 ignored |

[C5 GitHub CI 快照与实际失败](ci-c5/README.md) 单独记录远端状态。05:20 UTC 的 104 checks 为 48 success、8 failure、45 in progress、3 skipped，尚非全局终态；本地通过不表示远端全绿。

mandatory W1 为 151 项，645 个 PQ source pins 仍以原严格规则验证且资格结论保持 HOLD。两 crate strict Clippy、自有 Rust fmt、locked/offline Cargo 图和实际 compiler artifact 均核对。实际 costly/cold 两次入口另列，未把 ignored 数量或验证重复次数算作完整生成样本。没有重跑历史 native 243 项全套，也没有建立完整 SQLite I/O owner-domain 业务预算资格。

## 3. 修复了真实证据接收反例

[绑定反例与修复](evidence-binding/README.md) 记录旧 C3 reader 接受把真实 verifier 内部时间从 33,114,440 ns 改为 1 ns、却保留旧 observer digest 的副本。旧审计器还接受整数 0 变为布尔 false。新实现绑定真正读取的字节，严格验证 UTF-8、重复键、有限值、递归类型、原时钟、真实退出及最终输入 pins；未闭合之前不发布成功身份。

开发阶段的历史控制使用当时可读的旧 verifier；最终 11 项真实 receiver 明确使用新 C5 verifier。旧 ELF 路径后来缺失造成的 C4 pre-test 失败原件仍保留，不把零执行测试算作通过。

## 4. 完整生成与 admission 仍有具体阻塞

[原 winner header 与 admission 诊断](winner-admission/README.md) 逐字解码/重编码了 318-byte PNH1。现有保留原件未提供与其固定 parent 和承诺匹配的合法 Node 父状态及事务上下文；native winner 也未检查 parent eligibility。当前 Growth Node 使用 354-byte PGH2 和 growth challenge 域。现有原件没有证明同一中奖声明已被真实 Node 接纳；针对这两份旧证明所对应中奖 W1 的实际 submit/negative admission 事件均为 0。

[完整生成 ABBA 草案](full-generation-abba-plan/README.md) 仅准备 A/B 同资源参数。原 preparation 仍为 prepared_not_executed，source_constraint 仍引用 A d3037c…，冻结 source/tree 和 runner/native/verifier/guest ELF 字段为 null。先需要合法 Node candidate、同候选 native admission 与对应 proving interface，再固定所有执行 pins、创建新操作/新 deadline，才能执行该比较。不能称为 C5 已就绪的执行计划。

[原 80 行严格审计](abba-audit/README.md) 的两个 per-block 均值比中位数为 12.0628448679 / 13.7398970544；原边际中位数比仍是 13.0634904873 / 13.4308277868。全部 20 个 block 中 proof 验证更慢；receipt/native payload 为 5.191573 倍。这些都是旧完整 receipt 的重复验证，新增生成数为 0，没有总体 p99 或因果生成加速结论。

## 5. 进程、隔离与资金边界

[Collector 控制](collector-controls.md) 保留首次失败、修复及最终 14 项实际控制。单独 subreaper 只拥有新 command 的 wait 域，使用 boot/PID birth、pidfd、waitid/wait4 和实际 caller exit；原 target 的 dispatch→worker→exec 有限载荷真实运行。最终 ECHILD 的含义限制在该存活 collector 所拥有/收养的可等待后代，不能补齐其他父进程已回收的全部历史孩子。额外真实 SIGKILL 控制和原始证据在 qualification 归档中。

[系统级 CPU 隔离探针](cpu-system-scope/README.md) 12/12 条件实际通过：7 个真实 GPU 设备共 28 次 open 全部拒绝，并完成 socket、ptrace、继承 fd 及 null/zero 正向控制。该新短探针未运行完整 zkVM，不能回填旧任务的 GPU=0 或完整资源计费。

[旧取消费用独立审计](old-cancellation-fees/README.md) 从原 config/wire 推导 Reserve 419、Cancel 291，重新验证两个 Ed25519 签名。本金 1000 对应取消净增 709、Reserve+Cancel 净减 710。原只读副本 SHA 前后相同；该审计没有产生新资金动作。

## 6. 保留业务失败与资格限制

[C3 公开 CI 原件](ci-c3/README.md) 固定三个 campaign 的 9 个原 30 秒阶段，finite criteria 均未通过；baseline 各只确认计划 3 项中的 1 项，压力阶段均为 0/3。4 秒、0.25 CPU、2 GiB 的相关控制也存在实际业务失败。这些 C3 记录不是本轮重跑，不能由新的普通测试通过覆盖。[C5 当前 CI](ci-c5/README.md) 另外实际产生了新的失败：3 次 native campaign 的 9 个原 30 秒阶段全部 finite=false；fresh-service 的 head/merge 两 lane 未通过原 4 秒／6 层目标；4 个 protocol/cost job 在确认目标失败。另有一项历史 artifact 缺失导致诊断未执行，不能混作业务失败。

[机器可读总表](summary.json) 将各工程门及部署、资源计费、业务预算和完整密码学/协议安全资格明确保持 HOLD/false。当前最关键的后续依赖依次是：合法同声明 Node admission 与 proving interface；冻结输入后完整生成的同资源重复实验；执行时可审计的全历史资源所有权与计费；在合法完成/结算条件成立后验证一次性正向 provider 付款；最后在原业务资源和真实网络条件下验证端到端收益。
