# C7 固定 base96 整合与本地冻结原件

本包记录 C6 上合入固定 base96、必要的生成清单修复、候选控制及本地 commit。最终源码为 `40a3a45d6b8afc5c4706c5235fec47634f4aabbe`，tree `4b25e3194a0682adff40bb476f2e7c0a395639fe`；两个有序父提交是 C6 `2bdd252aa6c300b7431b9ee897b254b7953cf562` 与 base96 `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`。本包不代表提交后的精确源码资格，也没有新 operation、完整 proof、CI rerun 或 push。

## 实际范围

正常合并原有 6 个路径、1120 行新增且无删除；未加计划段和生成清单修复时的 index tree 精确为 `d73e57c9e7a5764a1ab33540c97af587bb6e4a69`。新增内容为 4 个独立 History diagnostic 文件、Host helper 的 6 行，以及 corpus 的 5 个 pin／required 条目。

候选检查实际发现 embedded source inventory 缺少新 Rust integration test。原失败保留；使用仓库原生成器仅注册 `tests/history_stage_diagnostic.rs`，1278→1279 个文件、7 行，无删除。其既有 corpus blob pin 从 `5076e6953e98868fae50d95e9e47db14b65929ea` 精确更新为 `c4fd4e40d80c2a2d0387c23432c56c57ca3fe135`，其他旧 pin 值与 corpus 字段不变。最终有 650 个精确 pin 和 558 个 required 路径；原 645 个 pin 路径、553 个 required 路径及 required 原顺序全部保留。

唯一计划文件只追加一个段落，说明 C6 已执行的生命周期、原失败保留、新 base 的范围和 C7 尚待的新事件／精确资格。最终对 C6 的实际 diff 为 **8 个文件、1131 行新增、1 行删除**；不能把静态 d73 预览当成最终 C7 tree。生产 Rust `src`、M12、W1 生成及 CI guard／事件上下文没有修改。

## 每次尝试分别保留

| 尝试 | 实际结果 | 边界 |
| --- | --- | --- |
| Setup 01 | 准备脚本 exit 1 | 不存在分支的 `show-ref --verify` 实际返回 128，驱动错误预期 1；在创建 worktree／merge 之前停止，0 测试 |
| Merge preparation 02 | 18 条命令 exit 0 | 正常建立独立 worktree、无冲突 merge；旧 C6 checkout 仍 clean |
| Precommit 01 | 12 条命令中仅 inventory 检查 exit 1 | History 6、Host 79、PQ 39、W1PostwinLaneTests 10，合计 134 PASS，0 skip；不把 inventory 失败改写为通过 |
| Inventory 只读差量 | 实际外部 render 核对通过 | 只确认新增一项清单登记，不执行 Rust workload |
| Repair 01 | 10 条命令 exit 0 | 原生成器刷新、精确 pin 重绑；inventory／PQ／CI／fmt 通过；PQ 39 + W1 CI 10 是另 49 次重复方法执行 |
| Freeze 原请求 1899 | `launch_unknown` 原状态保留 | 不把未知启动称为成功，也没有直接换 key 重复执行 |
| 只读调和 18af | exit 0、complete/durable | 原 remote jobdir、system/user owned unit、freeze 输出均不存在；HEAD/MERGE_HEAD 和已检查 diff 未改变 |
| 唯一受控续行 18c2 | exit 0、complete/durable | 启动前重复核对上述条件，使用相同 create-only `freeze-01` 原子占用；实际 commit，未 push |

原请求没有到达 freeze 脚本最前面的 mkdir；只读调和保留两类 unit 的 not-found／PID0／空 InvocationID，以及 diff SHA256 `511a8c21cf92b15451e43a8aa44f66dcf6f548f5a5b469ef8f39ef7848ffa9fa`。协调者明确授权一次受控续行，入口再次核原状态，atomic claim 阻止晚到的重复执行。该过程没有改源码来绕过运行通道或 CI gate。

## CI 上下文边界

[只读上下文审阅](context-review/README.md) 记录原 PR 事件 base62 与实际 merge 的 base96/C6 父提交不一致。38 个 prospective-merge lane 与 1 个 CodeQL export 的前置拒绝符合现有身份规则；另一个 retained artifact 失败须单独解释。原时点 snapshot 含运行中 checks，不是最终 CI 总裁决。

C7 必须有新的事件 candidate/base/merge tuple 读回，并在其精确 commit/tree 上单独取得构建和执行资格。本包的 134 + 49 为提交前的方法执行，49 项重复；不是新的 postcommit 资格分母。History 的 6 项是本地控制，完整 4105 blocks 的真实 workload 没有在这里执行。C6 的旧 proof、操作及 D4 原件不由 C7 候选检查重写。

## 文件与归档规则

[summary.json](summary.json) 汇总事实，[source-freeze.original.json](source-freeze.original.json) 保留实际 commit、parents、原命令和计数，[inventory-repair.original.json](inventory-repair.original.json) 保留生成清单与 pin 的完整哈希。[raw-output-index.json](raw-output-index.json) 将每个原路径、字节数、SHA256 对应到 [raw-logs.tar.gz](raw-logs.tar.gz) 的唯一成员；归档后逐件读回核对。

录入仅使用明确 allowlist：命令 stdout/stderr、JSON 回执、diff、计划片段和已执行驱动。没有 ELF、SQLite、整个 state tree、实际进程环境转储或凭据。原失败、来源不确定和后续修复分开呈现；四门资格仍须读取各自独立证据。
