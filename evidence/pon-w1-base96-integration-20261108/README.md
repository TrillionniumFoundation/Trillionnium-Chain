# W1 C7：精确源码资格、启动 Unknown 与发布完整性修正

本归档固定 **C7 `40a3a45d6b8afc5c4706c5235fec47634f4aabbe` / tree `4b25e3194a0682adff40bb476f2e7c0a395639fe`**。源码已普通快进推送至 [PR #782](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/782)，PR 保持 Draft。

**69 条资格命令、655 次普通方法执行通过，另 4 ignored。C7 新昂贵研究任务停在 launch-Unknown；没有可报告的 C7 自然超时、取消退款、重组或冷恢复成功。四个部署／安全工程门继续 HOLD。** 此文档提交并不是上述实际执行的源码提交。

## 1. 本轮交付与明确边界

| 项目 | 实际结果 | 资格边界 |
| --- | --- | --- |
| 精确 C7 源码 | core、owner、receiver、backend、native、History local、staged 七组完成；独立重读 138 份 stdout/stderr | 绑定 C7，不覆盖此后移动的 base 或后续候选 |
| 新 owner 产物 | 新空 target 的创建、device/inode 和 exec 前 0 entries 有原件；37 PASS、4 ignored | registry/toolchain 复用，不是独立 cleanroom |
| backend/native | 两个独立复制缓存，顺序重新构建；Cargo/source/ELF 与 source probe 都核验 | copied cache，fresh_cargo_target=false；Cargo artifact 的 fresh=false 表示本次重编译 |
| receiver | 新 C7 verifier 对历史真实 proof/input/header/独立 expected-artifacts 完成 11 项 | 0 新完整证明；不建立部署 WAN 或同 winner 的 Node admission |
| History local | release 编译并精确列出 1 个 ignored 入口 | 0 个方法通过计数；未执行 4105-block 完整 workload |
| staged | 所有六个当前已知资格 job 终态后，原参数单独运行 32 项，一次通过 | 不推论整机空闲，不重写 C6 首轮失败 |
| 新昂贵研究意图 | prepared intent 已绑定 C7、owner、runner 及七组资格；外层启动 Unknown | 未形成可确认的实际应用生命周期，禁止转记 C5/C6 的运行结果 |
| 旧证据发布修复 | 104 个被 ignore 排除的原始日志按原哈希补齐 | 不增加测试、证明、付款或资源资格 |

入口：[精确资格与独立审计](qualification/README.md)、[缓存与 owner 导入](build-preparation/README.md)、[C7 启动 Unknown](lifecycle-c7/README.md)、[发布完整性更正](publication-completeness/README.md)。

## 2. 精确源码结果

| 组件 | 命令数 | 原始输出独立复算 |
| --- | ---: | --- |
| Core | 20 | Python 571 PASS |
| Owner | 19 | Rust 37 PASS、4 ignored |
| Receiver | 4 | Python 11 PASS、0 skip |
| Backend | 7 | 构建与源码 probe 合同通过；unknown-stage 的预声明 exit 1 保留 |
| Native | 10 | Rust 4 PASS |
| History local | 5 | 编译与 list 成功，0 PASS |
| Staged | 4 | Python 32 PASS、0 skip |
| **合计** | **69** | **614 Python + 41 Rust = 655 普通 PASS；4 ignored** |

69 条命令中，68 条 exit 0，另 1 条为源码验证通过后触发的预期 unknown-stage 负控。预提交检查、owner 导入、独立审计和发布核对不再加进这个方法执行分母。History 的 1 个列举入口也不算执行通过或 ignored 执行次数。

原 generic driver 保持字节不变，SHA-256 为 `d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f`。Staged 保留原 0.15s / 0.2s 等 fixture 参数；启动记录核对了六组已知 job 的 manifest、实际 inactive/PID0 状态和当前 cgroup 范围。这里没有关于整个主机无其他负载或全部历史后代已回收的结论。

独立审计首次误加“当前 Cargo ELF 必须 nlink=1”的限制并 exit 1，原件完整保留。初始缓存复制的 inode 隔离与 Cargo 随后产生的内部 hardlink alias 是不同观察；修正审计器后只续读剩余原件，没有重跑资格测试，也没有把这次审计器错误记成资格失败。

### 实际产物

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| owner test ELF | 467,950,280 | `ae9ebf85ec7b76ea38c0ca1649d5a5e16f0015c915653eeea486c5090c3ce3c7` |
| staged prover | 47,813,072 | `268a2a56a4896aa8da926937f1643c9d2c3dfc690f9b6e3ffa1c7d7e2858dd46` |
| verifier | 19,343,864 | `93a1721d829846da2a4ab01f41238cf5d95351ce002556cc0840d009629e4219` |
| native winner | 752,472 | `753c8c3610dcf0687e2d54f19e5c5b307dd54683bedabc7fe3d39eed57ee4b03` |

Owner 的独立 import 验证原 19 命令／38 输出、唯一 Cargo artifact、C7 compiled-checkout 与实际 ELF。第二位审计者明确没有重复大读 owner ELF，沿用被绑定 import 的 SHA，并独立核其 Cargo 原件、空 target 来源和输出；没有冒充两次独立 ELF 全字节读取。

## 3. C7 昂贵任务：保留 Unknown

Prepared intent：

`b515f62d1a8ade59f4bf3a01ae5ef774d463ed43adc129de88602555cca945c1`

原 plan SHA-256：

`3fc21976c7c60c705d12080126ebf090c81d9f01bec182b94f679fa073429591`

Prepare job `1a1ba4b4ca5-12894-198a` 成功，研究计划为 8 CPU / 8 GiB、segment workers 2、compression workers 2、Rayon 4，原 120 秒只应在实际 launch 时选择。Prepare 没有选 deadline。

唯一外层请求 `1a1ba4cf251-12894-1994` 返回 launch_unknown。同 idempotency key、同 argv、同预算的调和返回 reused=true、retried_launch=false，工具没有重新启动请求。最后有界只读观察中，原 jobdir、exact unit/cgroup，以及 config、launch declaration、run、research-node、target-state 未见；末次 process_status 仍报告远端 jobdir 不存在。观察没有发出信号。

这些是具体时点的缺席观察，不能证明从未执行，也不能把不存在 unit 的 Result=success 当成业务成功。**本轮没有已确立的 C7 实际 deadline、M12 状态、资金 Reserve、cap 保留／消耗、退款、reorg、cold 或完整 proof。** 未换 key、未改走另一启动路径、未重派该意图，原请求和所有 Unknown 原件保持不变。

此前 [C5 证据](../pon-w1-four-gates-20261108/README.md) 与 [C6 证据](../pon-w1-base62-integration-20261108/README.md) 中的真实昂贵启动、自然 deadline、显式 veto/Cancel、有效分叉移除／恢复同一 Cancel、独立冷恢复保持原源码和 operation 身份。C6 原 target 在其 120s deadline 后 0.390722375s 终态；这些事实不转记为 C7 执行。

C5/C6 使用隔离的确定性研究 Node fixture；gross 1000 本金记录不能跨样本相加为全局新退款，也不是扣费后净额。原两个 Pending 操作与其 cap 没有被本轮改写，正向 provider 付款及完整资源结算仍未建立。

## 4. 发布完整性更正

先前校验覆盖了本地文件和 README API 读回，没有覆盖每个 inventory 成员的 Git blob。D5 的新 worktree 揭露 `.gitignore:23:*.log` 排除了 **104** 个保留的原始日志：

| 原包 | Inventory 成员 | 旧 D4 Git 树实际成员 | 缺失日志 | 缺失字节 |
| --- | ---: | ---: | ---: | ---: |
| C5 | 421 | 346 | 75 | 1,000,778 |
| C6 | 472 | 443 | 29 | 7,438 |
| 合计 | 893 | 789 | **104** | **1,008,216** |

两个 inventory JSON 本身已被跟踪。因此“本地 422 + 473 个文件均完整”不能作为旧提交中所有文件已公开的证明。PR 正文已公开这一更正。

本提交补入相同的 104 个原件；原 inventory、已跟踪文件、旧提交和原始失败字节保持不变。**895 个旧路径（893 成员及两个 inventory）**均从 Git index 逐个读回大小和 SHA。最终出版继续对旧包和新包的 index／commit／GitHub tree 逐项核对，避免再次把文件系统存在等同已发布。详见 [原始审计及修复清单](publication-completeness/README.md)。

## 5. C6 远端新失败：业务门仍 HOLD

[后续原始 CI 证据](ci-c6-followup/README.md) 固定一次 08:10 UTC 的精确分页快照：105 checks，58 failure、42 success、3 skipped、2 running。这是该时点结果，不是最终状态。

相比此前 40 个失败，新出现 18 个：10 个 source/ordered-parent 前置失败，8 个实际进入业务执行。已审元数据合计为 49 个 source gate、1 个历史 artifact 缺失、8 个实际执行失败，不能把所有失败归为源码身份问题。

关键实际样本：

- 五个 from-zero 失败样本的 5 项 native 控制均通过；原 4s、16 hostile workers 条件下，baseline 1/1、pressure 0/1，pressure 报 PUBLIC_REQUEST_DEADLINE。确认报告 invariant_target_met=true、finite_target_met=false，acceptance 因此拒绝。
- C6 原 History 在生成 4105 块后，只观察到 3853 次成功返回的 import call；原 1800s server lifetime 到期，后续 RPC 连接拒绝，Rust exit 101。成功返回的 call 数不能当作 durable committed blocks。
- 新的 base96 History diagnostic 副本 1 同样到达原 1800s server lifetime，记录 2759 次完成 import call，durable_committed_blocks=null，之后连接拒绝／exit 101。副本 2 job/log 是 success，但原 artifact 下载到 120s 只得到 partial；读取失败不转记为业务失败，也不据未读完的 artifact 推出完整诊断资格。
- 三轮原 campaign 的 phase 预算仍各 30s，压力配置仍为原 (0,24,24)。baseline round0 在约 16 秒确认，round1 未在原窗内确认；两个压力模式只观察到 round0，均未完成原窗目标。计划分母保持原样，未观测轮次不被删除。

这些是不同 source／不同诊断配置的实际失败记录，不用于推导因果回归或跨方案加速。Controller 的 4 CPU / 16 GiB 与 receiver/verifier 的 0.25 CPU / 2 GiB 分开记录。

## 6. 移动 base、真实冲突与 C7 CI

C7 的源码父提交为 [C6, base96]。已公开的 [base91 静态观察](base91-observation/README.md) 仅覆盖后续 3-path History 自引用修正；没有将其静态 clean tree 计为运行资格。

C7 push 前后，实际 base 从 `91c1b7…` 推进到 `9417e495165865ef6c1288b39084856e31020634`；REST base 从 62d2… 变为 96a241…，API merge 暂为 null，旧 merge ref 仍指向 C6 的 7b4a63…。这些读取并非原子快照。

9417 是生产代码变更，调整 store 的历史重放算术缓存和当前父块，并增加回归测试。其与 C7 的实际 merge-tree exit 1，在 workflow 和 corpus pins 两处产生冲突；输出的冲突树不是已冻结候选或合格源码。详见 [base9417 原始观察](base9417-observation/README.md)。

[有界 C7 远端读回](ci-c7/README.md) 中，REST mergeable=false/dirty、merge_commit_sha=null，精确 C7 check-runs 为 0。未观测到新 job 的 EXPECTED_BASE/HEAD/MERGE tuple；REST base 不是新 workflow event 的替代品，旧 7b4a63… 也不是 C7 merge。没有据此宣称 C7 CI 全绿或身份问题已修复。

GitHub 官方说明 [github.event 是触发该 workflow 的 webhook payload](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context)，且 [merge ref 可以过期、mergeability 需后台计算](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-your-git-database#checking-mergeability-of-pull-requests)。本归档没有把 base.sha 重新定义成 merge-base，也没有从 merge 第一父反填 expected 或放宽 ordered-parent guard。

因 9417 导致真实生产差量和两处合并冲突，后续 C8 在独立工作树处理；C7 原件和资格在本归档固定，不借后续结果回写。

## 7. 四个工程门

| 工程门 | 已建立 | 继续 HOLD |
| --- | --- | --- |
| 实际 winner／receiver | 两份历史完整证明本地及 ROG 严格接收；C7 新 verifier 的 11 项实际 receiver 控制 | 部署 WAN；同一真实中奖 W1 的 Node admission；全部历史进程所有权／回收／计费 |
| 完整后端同资源实验 | 历史两份 fresh 完整生成各 43 新 segment／43 lift／42 join；80 行验证阶段 ABBA 原件保留 | 完整生成仍各 n=1、配置不同；新完整生成 ABBA 未执行；原业务预算失败；无总体尾延迟或因果加速结论 |
| 真实异步服务与结算 | C5/C6 真实昂贵自然超时／Cancel／reorg／cold；C7 编译与短控完成 | C7 新启动 Unknown；旧 Pending/cap；正向付款、完整消耗计费与结算 |
| 部署收益与安全 | 独立 expected-artifacts、严格 raw/type/source 绑定及失败证据 | 原 4s／0.25 CPU／2GiB 完整证明资格；验证／传输收益；完整密码学和协议安全资格 |

0 新完整证明；没有部署、激活、自批准或合并受保护主分支。
