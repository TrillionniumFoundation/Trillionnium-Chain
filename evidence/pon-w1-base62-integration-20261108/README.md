# W1 四门：C6 精确源码、真实超时重组与事后证据

本轮在冻结 C6 上实际完成了昂贵 r0vm 启动、原 deadline 自然终止、Failure Unknown 对账、显式 owner 取消与研究本金退款、有效分叉移除并恢复同一 Cancel、独立新进程 cold。主入口 1 项通过，含收尾 123.43 秒；独立 cold 1 项通过，0.35 秒。新增完整 proof 为 0，完整资源计费、正向 provider 付款和部署资格继续 HOLD。

运行源码是 [C6 2bdd252aa6c300b7431b9ee897b254b7953cf562](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2bdd252aa6c300b7431b9ee897b254b7953cf562)，tree 为 ac3cb7171c429fa5e12e29ee16839fa6f49f1b81。本目录是事后文档，不是被执行源码。C6 已普通快进推送至 [PR #782](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/782)，保持 draft。

## 四个工程门

| 工程门 | 本轮取得的实际进展 | 仍未闭合 |
| --- | --- | --- |
| 实际 winner／receiver | 保留两份旧完整 fresh proof 与本地、ROG 独立接收原件；新 C6 verifier 的 11 项真实 receiver 控制通过。新 C6 target 的原 deadline 终态、同 job 冷读回已取得。 | 部署 WAN、中奖 W1 的真实 Node admission、完整历史进程所有权／wait-reap／资源计费。资金研究 Node 的维护块不能替代中奖 W1 admission。 |
| 完整后端同资源实验 | 原 80 行、20 个 ABBA block 的 verification-only 重审保留；新 C6 backend 实际构建、源码探针与昂贵启动完成。 | 两个完整生成方案仍各 n=1，原配置差异保留。完整生成 ABBA 仍是 source／ELF／合法候选 pins 未绑定的参数草案，未执行，不能给出总体尾延迟或因果加速。 |
| 真实异步服务接线 | 在 C5 已成功的路径之外，C6 新 generation operation 又完成原 120 秒自然超时、Failure Unknown、owner veto、普通 NativeCancel、真实 fork 重组与独立 cold；本地派发读回 Done，禁止重派。 | 旧两个相关操作与此前失败操作保持各自原 Pending／cap 事实。Done 只关闭派发；consumed=null、全资源 cap 保留，无 Positive／provider 付款或完整资源结算。 |
| 部署收益与安全资格 | 保留完整 v2 expected-artifacts 绑定、真实字节摘要与严格类型负控；当前实际源码、构建来源、失败尝试和独立核验分别归档。 | 验证／传输部署收益、原业务预算、完整密码学及协议安全资格均未建立。短控制和研究窗口不替代这些门槛。 |

旧完整证明及 80 行验证结果来自 [C5 四门原件](../pon-w1-four-gates-20261108/README.md)。该包的 421 个清单成员与清单本身共 422 个文件逐字节保留。C5 本地普通测试、C5 真实操作、C5 远端业务失败与本目录 C6 结果分开记录。

## 精确源码与资格：保留首轮失败

C6 的有序父提交为 C5 034aa74358e0a5fa33f33e83cb63669e9738da4b 与 base62 62d2d90c9e1f4c8450c89843f1e08360a24283ce。它合入 genesis ReorgStep 的 staging arithmetic 保护和 legacy reorg 负控加强；实际合并 bytes 的三处 pin 更新保留全部 645 个校验。20 个独立抽核的 W1 reader、source guard、deadline、owner terminal 和 cap 源文件与 C5 相同。合并前的 52 项 pin 控制另列，不计入下面的冻结后方法数。

| 组件／尝试 | 实际命令记录 | 实际结果 |
| --- | ---: | --- |
| core 首轮 | 19 | 518 个方法结果：516 PASS、2 FAIL、0 skip；整个作业 exit 1，qualification_complete=false。只有 staged observer 命令非零。 |
| owner | 19 | 37 PASS、0 FAIL；另 4 个 heavy 入口 ignored。M12／Node strict Clippy、自有 fmt、Cargo graph 与前后源码检查通过。 |
| native／verifier | 10 | 2 + 2 PASS；实际 build 和前后源码检查通过。独立 target-preparation 回执不是第 11 条命令。 |
| real receiver | 4 | 11 PASS，使用新 C6 verifier；新增 proof 为 0。 |
| backend 第一次 | 未形成完整资格 manifest | 原 900 秒作业 timed_out／124。最后 4 条已完成命令为 0，host-v2 build 未形成完整命令结果；当时目标 runner 仍是旧 C5 字节，不能授予 C6 资格。 |
| backend 第二次 | 7 | 全部符合预声明：6 条 exit 0，真实 C6 source-probe 在验证源码后因 unknown stage 按预期 exit 1。新 output、1,800 秒资格预算；复用失败 C6 build cache，fresh_target=false。 |
| 唯一隔离 staged 复核 | 4 | 同 C6、同 driver、同完整 32 方法 argv 和原参数，32 PASS。30 个是重复通过，2 个补足原失败方法；首轮结果不改写。 |

五组件首轮普通队列共 570 个方法结果：568 PASS、2 FAIL，另 4 ignored；隔离复核另有 32 PASS。它们不是 602 个不同方法，也不是 570 个方法一次全绿。C5 原汇总仍是 59 条命令、570 个普通测试通过；独立复核确认其 backend 7、native 10 的原计数正确。

首轮两项失败都得到 DEADLINE_EXHAUSTED_BEFORE_SPAWN，未触及它们预期的真实 TIMEOUT／SIGKILL 路径。其原 wall_seconds 为 0.15／0.20 秒，包含声明落盘等启动前准备。ignored-SIGTERM 方法的首个 assertion 失败，后续 OUTPUT_LIMIT 子例当次没有执行；实际默认 cleanup grace 仍是 5 秒。并行 I/O 是合理假说，现有记录不证明因果。一次隔离通过仅证明所记条件下触及这些分支，不证明任意负载下的稳定性。

隔离复核预先限制为一次；启动前保存各已知作业终态及其 systemd／cgroup 当前观察，全部已知构建／全源校验均结束。没有修改 C6、测试参数、生产计时逻辑或旧操作 deadline。全部原始输出、逐文件 hash、实际 argv、独立计数及来源边界见 [资格审计](qualification/README.md)。

## C6 新的真实 120 秒路径

新 generation operation：

8058cfa81675504da3f0593b8df7c51cb0b1f3fd6db1daa4d3f83172a6d4eacc

资源为 8 CPU／8 GiB、固定 CPU affinity、segment workers=2、compression workers=2、Rayon=4，预算 120,000,000,000 ns。原 guest 与 r0vm 仅验证保留字节，没有重新编译 guest。

| 同一原 clock 中的事件 | monotonic ns |
| --- | ---: |
| 原期限选择 | 1199223004629858 |
| 实际 r0vm live 观察 | 1199255881430349 |
| 唯一原 deadline | 1199343004629858 |
| target 终态观察 | 1199343395352233 |

r0vm 实际进入 prove-batch-0000，约在选择期限后 32.876800491 秒被观察为存活。target 终态为 original-deadline、exit -9、sticky_cancel=false；终态观察晚于原 deadline 0.390722375 秒。这是终止观察延迟，不是完整 proof 生成耗时，也不构成延长预算。

随后记录 Failure Unknown（consumed=null），再持久化显式 owner veto、普通 NativeCancel 与研究本金退款。更长有效 fork 移除原 Cancel 后，实际 Node 回到 Reserved／1000，原退款的 canonical claim 为 false；实际冷开 Node／M12后仍禁止重派。延长原 ancestry 恢复同一原 wire、packet 和 inclusion，无新签名、无新 Cancel。独立新进程 cold 沿原 operation／statement／deadline读回 Done：0 dispatch、0 target cancel、0 native transaction。

**资金范围是独立研究 Node。** C6 generation operation 与数据库目录是新的；固定 fixture 的 NativeTask Cancel ID、wire、packet 与 C5 可以逐字节相同。这不代表复用了旧 Node，也不证明全局链上的新资金、跨 fixture 唯一性或累计两次真实链退款。1000 为研究本金总额，不能当作扣费后的账户净增或 provider 收款。

实际热／冷 target 完全一致，原 Cancel 恢复前后内容一致。最终只读观察的原 parent／child cgroup 均不存在，6 个已知原 PID birth 均不在；0 signals。此项当前观察不补足未采集的完整历史后代 wait／reap。GPU 使用、memory peak、完整资源计费仍未知，所有原 cap 保留，无正向 provider 付款。见 [完整 C6 生命周期与列明原件](lifecycle-c6/README.md)。

## 构建来源与失败尝试

owner 与 native03 各自从经原始创建／启动前回执确认的独立空 target 构建；registry 与 toolchain 复用，不能称为 cleanroom。backend 使用独立复制缓存；首轮 900 秒失败后，冻结原日志和未获 C6 资格的旧 ELF，再以全新输出和独立 1,800 秒资格预算复核。该预算不修改真实操作的 120 秒期限。

复制阶段的 owner 取消（exit -15）、backend/native 整体超时（124）、backend 组件完成、native partial，以及 native02 launch／terminal Unknown 分别保留。native03 独立起点不会冲销 native02 Unknown；partial、组件完成、整体失败不能互换。见 [构建准备原件](build-preparation/README.md)。

## 新 base96 与 PR 边界

资格期间，实际 integration base 又推进到 96a241bf43f6a46d35dfb3d4ced9594ed8ceca75，其唯一父提交为 base62。它新增历史阶段诊断及测试、扩展共享 Host helper，并更新 pins；六个路径、1120 行新增，无生产 Rust src／M12／W1 generation／collector 源码变更。它包含可执行诊断，不能简称为只有文档。

C6 与 base96 的静态 merge-tree 无文本冲突，假设合并 tree 为 d73e57c9e7a5764a1ab33540c97af587bb6e4a69。该静态结果不是运行资格；本地 C6 结果不转记成 base96 或该合并 tree 已执行。远端 Git ref 与 PR API base.sha 在读回时存在不同步，均按原值保留。见 [base96 只读观察](base96-observation/README.md) 与 [实际 source 推送读回](publication/source/readback.json)。

07:19:50 UTC 的 C6 远端快照共 85 个 check：40 failure、10 success、3 skipped、32 in progress。40 个失败的原 job steps 已逐一读取：38 个 prospective-merge 的第一失败步骤均为源码／有序合并绑定；已读多个类别的原日志显示 event base=base62，而实际 merge 的有序父提交为 base96+C6，严格 guard 正确拒绝。export 另因同一父序要求失败，其 16 个离线测试已通过；剩余一项是历史 artifact 不存在。目标业务步骤多处 skipped，不能把这些前置阻断当作 40 个业务实测回归。见 [C6 CI 原快照与诊断](ci-c6/README.md)。

实际 GitHub merge ref 为 7b4a63b6f08687e93270407772951aa71087ca3d，tree 与静态 d73 相同，parents=[base96,C6]。旧事件声明及失败不改写，guard/context 未放松；后续正常集成 base96 的新候选必须重新核对新事件 tuple，不能把新结果倒填此版本。旧 C5 的业务与压力 CI 失败原件也继续保留。原业务 4 秒／0.25 CPU／2 GiB 与完整 hostile-confirmation 矩阵，不因本地普通测试或宽研究窗口而通过。

## 证据入口

- [机器结果](summary.json)
- [资格原件、失败与独立复核](qualification/README.md)
- [真实 C6 重型路径与独立 cold](lifecycle-c6/README.md)
- [构建准备、复制失败与 Unknown](build-preparation/README.md)
- [base96 静态合并观察](base96-observation/README.md)
- [C6 远端 CI 快照与前置阻断](ci-c6/README.md)
- [逐文件发布清单](publication-inventory.json)
- [保留的 C5 四门证据](../pon-w1-four-gates-20261108/README.md)

公开目录采用明确 allowlist 和 SHA256 清单，不包含私有 SQLite、进程环境或凭据。无部署、激活、force push、自审批准或受保护主分支绕过。
