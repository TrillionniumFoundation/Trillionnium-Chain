# C8 精确源码资格、真实服务路径与完整公开证据

## 结论和范围

本包对应冻结源码 **C8 `4e007a87ceecbec8d265f6a70cfd71d512a514b5`**，tree `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`。源码父提交为 C7 `40a3a45d6b8afc5c4706c5235fec47634f4aabbe` 与基线 `9417e495165865ef6c1288b39084856e31020634`。本证据 merge 的父提交为 D5 `41d717cc9608153dec0daa26ad68ebf8129ed215` 与 C8；文档提交不冒充执行过的源码。

本轮包含首轮资格与一次预声明、参数不变的 staged 复核，共 **77 条命令：75 条 exit 0、一条预声明 source probe exit 1、一条真实 staged 测试失败 exit 1**。独立原始日志复核统计 **697 次普通测试方法执行，696 PASS / 1 FAIL，另 4 项 ignored**；其中 Python 为 645 PASS / 1 FAIL，Rust 为 51 PASS。154 份原始命令 stdout/stderr 流逐项重核。预提交、导入、审计和文档检查不混入这个分母。

首轮 73 条命令是 **664 PASS / 1 FAIL / 4 ignored**。唯一追加复核的 4 条命令、32 项测试通过后，每个指定组件均有一份成功的覆盖记录；这个选定覆盖集的 73 命令/665 PASS **不能替代完整累计，也不能证明首轮全绿或短时限控制稳定**。没有继续挑选第三次结果。

**四项工程门均保持 HOLD。** 此处精确源码功能资格不推出业务原资源预算、完整证明生成加速、正向 provider 付款、完整资源结算、部署 WAN、同一真实 W1 winner Node admission 或完整密码学/协议安全资格。

## 本次生产基线整合

基线 9417 相对其直接父提交 91c1 含真正的 store/historical commitment 缓存修改；C7 与它的实际静态 merge 出现 workflow 和 corpus 两处冲突。C8 在独立工作树中解决这两处具体冲突，保留基线生产变更及原 W1 源码保护，再冻结并重新执行资格。最终相对 C7 为 8 个路径、+208/-16；652 个源码 pin、560 个 required pin；分布式源码 inventory 身份仍为 `c4fd4e40d80c2a2d0387c23432c56c57ca3fe135`。

预提交的 9 条命令、160 次 Python PASS 单列在 integration 包中，不计入冻结后的 697 次普通执行。真实 expected event tuple、源码 guard、业务 deadline 和验收条件未放宽。新的上游 base 移动仅作为有时间边界的观察；本包不把 C8 结果转称为另一个 merge tree 的资格。

缓存静态审查只观察到保留偏好变化：Legacy snapshot anchor 与其前六个 replay descendants 可优先留存，仍受 entry 和 byte 上限控制；更换 anchor 清理偏好，byte 压力优先于保留偏好。缓存命中仍比对当前 SQL root 和实际 State 的规范字节；差异回退到原始完整准备路径，最终根与新鲜 expected root 比对。没有缓存或返回“已验证有效”的 State 结论。具体原件在 [基线静态审查](base9417-review/README.md)，实际 C8 10 方法执行见下表。软件 2 MiB payload / 16 MiB retained 记账上限不等同于 Node RSS 或完整进程树资源上限。

## 冻结后实际资格

| 组件 / attempt | 命令数 | 普通 PASS | 普通 FAIL | ignored | 边界 |
|---|---:|---:|---:|---:|---|
| 主控制 | 20 | 571 Python | 0 | 0 | 精确 C8 源码、CI、边界及 W1 控制；嵌套日志不重复计数 |
| M12 / Node owner | 19 | 37 Rust | 0 | 4 | 独立 copied target；严格导入保持 19 命令/38 原始流 |
| Receiver | 4 | 11 Python | 0 | 0 | C8 verifier + 历史完整 receipt；新 proof 为 0 |
| Backend | 7 | 0 | 0 | 0 | 实际 runner/source；unknown-stage probe exit 1 为预声明负控制 |
| Native / verifier | 10 | 4 Rust | 0 | 0 | 实际 native winner/verifier 构建与控制 |
| Historical cache | 4 | 10 Rust | 0 | 0 | 完整模块；扩展两个已有方法的断言不另增方法数 |
| History 本地 | 5 | 0 | 0 | 0 | release 编译 + exact ignored list；完整 4105 未执行 |
| Staged 首轮 | 4 | 31 Python | 1 Python | 0 | 原 0.2 秒用例在 spawn 前预算耗尽；qualification=false |
| Staged 唯一预声明复核 | 4 | 32 Python | 0 | 0 | 原源码/argv/参数/计划；完整两子段通过；不再追加复核 |
| **完整累计** | **77** | **696** | **1** | **4** | **697 次实际普通执行；75 零退出、1 预声明负控制、1 原失败命令** |

[独立资格核验](qualification/README.md) 保留每个组件的原 manifest、raw streams、source-before/after、实际 Cargo artifact 与产物身份。原 driver SHA256 保持 `d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f`。

### 构建来源和实际产物

C8 的 backend、native、owner target 均来自已完成 C7 target 的独立复制，**fresh target=false**。初始复制检查文件集合、metadata、inode 隔离和指定 ELF pin；不声称逐字节哈希所有缓存文件。owner 初始 3065 文件，backend 3921，native 2014。C7 owner 曾由空 target 构建，是历史来源事实；C8 不继承“本次从空目录构建”的表述。

| 实际 C8 产物 | 字节数 | SHA256 |
|---|---:|---|
| Owner test ELF | 467190280 | `1cc1db569c0d21f27aabc3ddbef4730ce11a6481c026b35ed69460c09028d456` |
| Staged runner | 47809632 | `258ec975410fddfb984d22671631851c459a8c18ff6424bdb3bce4e3ad124b99` |
| Verifier | 19346216 | `c667ec4cff650909734c4343fc814d0b3dd8bdb68b5c85085b11bd9c2d68cd2f` |
| Native winner | 752472 | `753c8c3610dcf0687e2d54f19e5c5b307dd54683bedabc7fe3d39eed57ee4b03` |

build-preparation 子包按首次 staged 失败时的截止点冻结，仍保留当时的 blocked 状态；后续唯一复核及真实服务进展分别在 qualification 和 lifecycle-c8 中追加，旧包未改写。

Cargo artifact 的 fresh 字段与 target 来源是不同概念。实际源码路径、Cargo JSON 和 ELF 的重核建立本次编译身份；重用 registry/toolchain 和复制缓存的事实保留在 [构建准备与严格导入](build-preparation/README.md)。

### 首轮 staged 失败和唯一复核

原 staged job `1a1ba8f182e-12894-1b97` 的 manifest `a6e8363bfa6a157fc1b414b64e4af59bb11211166fe06f1b0962460253e89e25` 保持 qualification=false。32 方法执行中 31 PASS / 1 FAIL，失败断言期待 SIGKILL_DURING_SETTLEMENT，实际仅有 DEADLINE_EXHAUSTED_BEFORE_SPAWN；随后同一方法中的 OUTPUT_LIMIT 子段没有执行。源码说明原 0.2 秒从 measure.started 开始，之后仍须写声明、打开日志，再检查预算并尝试 Popen。测试注册了 TemporaryDirectory.cleanup；保留的资格原件不含该单次控制的子目录及分阶段时点，不能证明具体 fsync、CPU 或 I/O 因果。七个已知资格 unit 已退出不等于整台 host 空闲。

在保留该失败、固定最多一次复核之后，声明 `7b51a7dee784b9375eb1c1dcc9b8f54869538810c763ee1514208ba42912ce95` 约束相同源码、argv、cwd、plan、driver、环境及原短时限。唯一 repeat job `1a1ba97e353-12894-1bcf` 实际 exit 0 / complete / durable，manifest `f7c7527fb00f542021f0c7ab0469b2c0f2905e0f71b9b55f5e577b8f94c3104f`，32 方法全部通过，包括先前未进入的 SIGKILL 与 OUTPUT_LIMIT 子段；不再追加测试。源前后均为同一干净 C8。

另一个保留的 fixture 限制：测试 patch 模块常量 TERMINATION_GRACE_SECONDS=.15，不改变 measure 定义时捕获的默认参数；run_control 没有显式传参，该调用的原默认是 5 秒。此次未悄改冻结源码，也未报告实际 cleanup grace 为 .15。复核成功补充了控制分支覆盖，未建立短时限稳定性或首轮失败的因果解释。

### 启动和审计更正原件

首次 owner wrapper 因计划写作 “Independent copy” 而 wrapper 只接受子串 “copied”，在启动资格 driver 前 exit 1。原 job `1a1ba70f3e9-12894-1ab5`、426 字节 stderr、原 plan 和 wrapper 全部保留；它执行了 0 条资格命令、0 项测试。v2 仅将该文案条件改为原 cache_basis 的精确字符串相等，并用独立 02 输出/binding，原 plan、源码、预算和全部实际复制/ELF/source guards 不变。后续实际 owner job `1a1ba7cdd03-12894-1b0d` 完成上表 19/37/4。

独立 backend/native 审计首轮错误携带旧源码 guard 文件哈希，先 fail-closed。更正仅作用于外部审计常量，原失败保留，不重新跑或修改资格。独立复核后的原件是本包统计依据。owner/historical 审核器还曾对 traceback 写错子串断言；原失败和仅修正外部审核器的记录同样保留，0 次新测试、0 次原资格改写。

Staged wrapper 执行前审查发现只检查父 cgroup.procs 的范围缺口。保留未执行的 v1，v2 增加 present cgroup 的 events populated=0 前后两次读回，以及递归所有 cgroup.procs 为空的检查。七组真实终态、精确源码/manifest/count、原 staged plan 和 driver pin 均保留。Linux [cgroup v2 官方说明](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html) 将 populated 定义为该组及子组的 live-process 状态；这些有界观察不证明 zombie reaping、历史所有进程归属、GPU 计费或整台 host 空闲。

## C8 独立真实服务路径

本轮创建了独立 C8 operation `a35153e046b91421e3d8d67c0d5f053b88a87f4f8ac8213f8e3ee09f5f1be1e9`，其准备记录绑定全部 77 条资格命令、原失败及唯一复核。prepare 阶段没有选择 deadline；唯一主路径 launch 按预声明的 8 CPU / 8 GiB、固定 CPU affinity、2 segment workers / 2 compression workers / Rayon 4 选择一次原 120 秒窗口。

实际观察到 `prove-batch-0000` 的 r0vm 活体，匹配已核验 runner 与进程出生身份。原 monotonic deadline 为 `1210689011653932` ns；目标 finished 观察为 `1210689304224509` ns，相差 **0.292570577 秒**。原终态为 `original-deadline / exit -9 / sticky_cancel=false`。这个差值描述目标终态观察相对 deadline 的位置，不是完整 proof 的完成耗时或尾延迟估计。

| 研究执行 | 原作业 | 实际终态 | 本次解释范围 |
|---|---|---|---|
| 主路径 | `1a1baa770fd-12894-1c3b` | succeeded / exit 0 / complete / durable；Rust 1 PASS / 122.68 s | 实际昂贵任务自然超时、typed Unknown、显式 veto/Cancel、合法分叉移除/恢复同一 Cancel |
| 独立冷恢复 | `1a1baac4fa2-12894-1c66` | succeeded / exit 0 / complete / durable；Rust 1 PASS / 0.32 s | 同一 config、operation、原 deadline；0 次新派发、0 笔 Native 交易、0 次目标 cancel |

原时间记录证明 typed Unknown 比显式 owner request 早 **1,995,728 ns**；超时本身未授权退款。后续接受取消的 outcome 没有独立时间戳，`journal_event_new=null / new_event_proven=false`，不另称证明了新的 journal append。原资金 Cancel 经合法分叉移除后，冷重开观察到 Reserved，再恢复原 Cancel 的同一 wire/packet/ancestry；没有另签 Cancel 或重派昂贵任务。独立冷恢复的 retained target 对象与主路径一致。分叉移除与实际 cold reopen 的 readback 都是 Reserved / remaining 1000；恢复后为 Cancelled / remaining 0。研究本金 1000 属于隔离 fixture，不作为净账户增量或跨实验累计退款。

最终新 operation 的 M12 调度状态是 **Done**，**consumed 仍为 null、完整资源 cap 保留、GPU 计费仍 Unknown**。Done 只描述调度终态，不等于全部资源账务结清或 provider 正向付款。两项研究 PASS 与普通资格的 697 次执行分列。

末次只读检查在原 boot 中核对五个已记录的 owner/worker/direct/runner/r0vm 出生身份，其当时均 ABSENT；原两个精确 cgroup 当时 ABSENT，main/cold exact unit 非活动、MainPID 0。未发送信号，也未从这些有界观察推断所有历史进程已经 wait/reap。子 cgroup 的局部 cpu_stat 不替代完整 consumed，历史所有权与全部资源计费仍未知。

独立窄审以 source-bound 原件复核上述时序、同一 target 与 Cancel，以及主/冷两份实际成功输出，未重开数据库或重验签名。审计 manifest 为 `849d4795981d9c2f2f5fc186b88d2b14b7f6d3882a21506d5f20fffe567d55b1`，结果未在此范围发现反证，完整安全资格仍未建立。

计划、主结果、typed failure、reorg、cold、gate 原件及末次观察见 [C8 生命周期证据](lifecycle-c8/README.md)。

C7 的原 launch Unknown 证据继续冻结：原 job `1a1ba4cf251-12894-1994`，same-key reconciliation 未重启；有限观察未见 unit/cgroup/job 目录或运行文件。未观察到不等于证明未执行。C8 使用独立源码身份和研究域；不将它解释为 C7 原请求重放或 C7 资格恢复。旧两个相关 operation 的 Pending/cap 状态也不由新 fixture 自动改变。

C5/C6 的实际原 120 秒自然超时、显式 veto/Cancel、合法分叉移除和恢复同一 Cancel、冷重开不重派，各保留自己的源码、deadline 和证据。本轮对 C5/C6/C8 原 Cancel 的 wire/packet 实际逐字节比对相等，并分别核对旧 plan/source/task 身份。三份确定性隔离 fixture 的同一 gross 1000 Cancel 不相加为全局累计退款；比对原件 SHA256 为 `7050666ab1fa07eabe099435be8c30ea4ef2da90d6e54640c8b4962509cc8bb7`。

## 远端 source / CI 观察

本次有界、非原子观察窗口为 **2026-11-08 10:22:55.303–10:24:36.474 UTC**。恰有两次 PR GET；固定 C8 的 checks / workflow runs 分页查询及最多六个已完成 job 样本，无 rerun、dispatch 或新增 base 整合。

| 观察集合 | 合计 | 成功 | 失败 | 未完成 | 跳过 |
|---|---:|---:|---:|---:|---:|
| Checks | 104 | 52 | 25 | 24 | 3 |
| Workflow runs | 15 | 4 | 5 | 6 | 0 |

同一批原始响应经独立 scope audit 复核：两类分页数量与唯一 ID 一致，foreign-source 列表均为空；六个样本的 job_id、run_id、head_sha、name 和 check_run_url 与原 check 对齐。原观察器的初版 enumeration-complete 谓词缺少这项身份条件，原结果保留；新增原件审核补上该范围核对，未重跑查询。scope audit SHA256 为 `5980096ddb4792e176b77fe3a36303b51ae27129fd55eb59f6b2d74dc55837f1`。

观察时 API 与实际 Git refs 均为 head C8 `4e007a87ceecbec8d265f6a70cfd71d512a514b5`、base `9417e495165865ef6c1288b39084856e31020634`、merge `a3b427a9f39e90176c9bfb48d85f9353fb2bd99b`。实际 merge parents 按顺序为 [9417, C8]，tree 为 `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`。该 tree 与 C8 head 相同，不据此替代该 merge 自己的远端执行资格。

| 已采样 job | 数量 | 原件支持的结果及范围 |
|---|---:|---|
| W1 original + fresh prospective | 2 | 源码前后检查步骤成功；原 log 明确打印 EXPECTED_BASE=9417、HEAD=C8、MERGE=a3b427；执行服务步骤非零。未取得内层报告，不声称具体 confirmation/finite 根因 |
| Cross-architecture prospective | 2 | 源码前后检查步骤成功；执行步骤非零。原 log 未打印完整 EXPECTED 声明，三字段保留 null；未取得内层报告 |
| CodeQL prospective | 1 | 实际成功；仅 EXPECTED_BASE 原声明可见，HEAD/MERGE 保留 null |
| Original native campaign head | 1 | 原 log 显示 build 成功，三轮均 return 101 / original_criteria_met=false；各轮 113.6226 / 113.4030 / 113.3158 秒。原 30 秒、0/24/24 业务条件保留；未满足原 campaign 验收。仅 HEAD 原声明可见，BASE/MERGE 保留 null |

上述六样本包含五个失败 check；其余 **20 个失败 check** 的首失败原因未采样，保持 unknown。24 个 checks 和 6 个 workflow runs 仍未完成，不能宣称全 CI 终态或通过。没有将 C6 的失败根因套到 C8；尤其没有在缺少内层报告时生成 CONFIRMATION_TARGET 或 finite=false 结论。

这是一份该时窗的历史快照；后续状态可变化。本包保留原请求、响应、实际 refs/merge 对象、样本日志及范围修正，见 [C8 CI 原件](ci-c8/README.md)。

仅实际 workflow/event 原件可以确定某次执行的 expected base/head/merge。当前 REST base、当前 Git base 和异步生成/残留 merge ref 分列，不互相替代；未观察字段保留 null。源码普通 fast-forward 与读回在 [发布记录](publication/README.md)。

## 四项工程门

| 工程门 | 本包可以支持的进展 | 仍未闭合 |
|---|---|---|
| 实际 winner / receiver | 原完整 proof 保留严格独立接收；新 C8 verifier/原件绑定控制；当前已知资格任务的有界退出观察 | 部署 WAN、同一真实 W1 winner 的合法 Node admission、完整历史树所有权/回收/资源计费 |
| 完整后端同资源实验 | 原两份完整 fresh proof 各 43 segment、43 lift、42 join；80 行 ABBA 仅是验证成本数据 | 完整生成每方案 n=1、配置差异；无总体尾延迟或因果加速；无原业务预算通过证据 |
| 异步 NativeTask / M12 | 原实际昂贵执行及本节分别列出的精确源码超时/取消/分叉/冷恢复证据 | 旧操作 Pending/cap、正向 provider 付款、完整 consumed / GPU / peak-memory 等计费及结算 |
| 部署收益与安全 | expected-artifacts、raw/type/source 绑定、预算和真实 CI 失败、完整公开字节检查 | 验证/传输收益、原资源业务资格、完整密码学/协议/部署安全资格 |

历史本地验证成本实验不能替代部署端到端收益。完整 proof 的历史长耗时、原资源预算失败和远端压力失败原件保留，不将扩大外层观察/编译预算称为原业务 deadline 通过。指定功能控制的成功也不清零业务失败历史。

## 公开完整性与证据导航

D5 已实际更正旧 D3/D4 的发布遗漏：C5 的 75 份及 C6 的 29 份原 .log 被 *.log 忽略规则漏入早期提交。按原 SHA256 恢复后，895 份旧文件与 1243 份 C7 文件共 **2138 个已跟踪文件路径** 已在 D5 commit 及远端三棵子树逐路径核对 Git blob 字节；不将共享同一 blob OID 的文件计为独立 Git 对象。旧提交和三个旧 inventory 的字节保持不变。D6 继续保留这些文件，并对第四个新证据包做相同完整路径/大小/SHA256/Git blob 检查。

- [Integration 原始合并、冲突解决和冻结](integration/README.md)
- [八组资格的独立 raw 复核](qualification/README.md)
- [复制来源、owner 启动失败及严格导入](build-preparation/README.md)
- [C8 实际服务路径原件](lifecycle-c8/README.md)
- [C8 有界远端 CI 观察](ci-c8/README.md)
- [基线生产缓存静态审查](base9417-review/README.md)
- [源码发布、D5 公布回执和本轮准备](publication/README.md)
- [完整新文件清单](publication-inventory.json)
- [Git index/commit 字节核验程序](verify_git_publication.py)

新 inventory 排除自身后逐文件列出大小和 SHA256；Git 核验同时检查 inventory 自身、四包精确路径集合及全部 blob 内容。提交后重核不可变 commit，push 后通过远端 immutable subtree API 比对全部 blob OID 并回读 README 原字节。D6 自身最终发布回执在 inventory 冻结后生成，不在本 inventory 中虚构自引用回执。
