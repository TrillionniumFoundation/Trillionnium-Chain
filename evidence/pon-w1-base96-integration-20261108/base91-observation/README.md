# C7 冻结后观察到的 base91：静态影响与清单一致性

本包观察固定上游提交 `91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c`，其唯一父提交为 C7 已集成的 base96 `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`。C7 仍为 `40a3a45d6b8afc5c4706c5235fec47634f4aabbe` / tree `4b25e3194a0682adff40bb476f2e7c0a395639fe`。本观察没有合并、创建 C8、改 C7 源码、执行测试、启动 operation 或 push；也不声称 base91 是发布时仍然最新的远端 base tip。

## 实际改动与适用范围

base96→base91 只有 3 个文件、5 行新增、3 行删除。Rust History diagnostic 写出的 `source.json.test_source` 从 `include_bytes!("ancestry_long_sync.rs")` 改为 `include_bytes!("history_stage_diagnostic.rs")`；既有 Python 方法增加两条断言，保证引用自身源码并排除旧文件名；corpus 同步这两个文件的精确 Git blob pin。Python 方法数仍为 6。

这是 History diagnostic 运行原件的来源标记修正。该差量没有生产 Rust `src`、M12、W1 完整生成、CI source guard 或事件上下文修改。C7 本地 History 资格只编译并列出 ignored 入口；实际写出该 `source.json` 的 4105-block workload 没有在这个本地步骤执行。观察不把旧 C7 的编译／运行回执标成 base91 资格，也不要求在没有相关运行代码改动的情况下无限重做已冻结的 C7 W1/M12 试验。未来执行完整 History diagnostic 应纳入该修正，并在其最终提交／树和实际 ELF 上重新绑定与核验。

## 静态可合并性

普通 `git merge-tree` 与 C7 现有 `verify_ci_source.py` 的隔离 canonical helper，均以有序输入 `[base91, C7]` 得到 tree `e8550e15374ce6a0cc60f435ccd4a0c401741930`。隔离 helper 排除了本地／全局配置和环境中的自定义 merge driver。两者均无冲突；没有实际 merge commit 或新工作树。

| 固定 pin | C7 | 静态合并树 |
| --- | --- | --- |
| `scripts/ci/test_history_stage_diagnostic.py` | `748b8417dbbbcc08ed3fd5b0cdb3b69c44bfd4c2` | `9fa491dd407ae0188142a0699791d620f14ac3f0` |
| `trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs` | `d6650671ccc93462623351d05fdf434d52669ce1` | `0ad34d092863dd32c5e9793daa618a91cd6c15f8` |

静态合并后的 corpus 仍有 650 个 source pins、558 个 required 路径。只有上表两项 pin 变化，其他字段与 required 顺序不变，C7 的生成清单 pin `c4fd4e40d80c2a2d0387c23432c56c57ca3fe135` 保留。数量不替代逐项字节／路径检查；原件记录了该逐项对照。

## 生成清单不会因同路径内容更新而过期

`distributed_source_inventory.rs` 保存路径登记及 `include_bytes!`，没有把旧 History 源码全文或旧摘要写成固定字面量。C7 与假设合并树的全部 15,390 个 tracked 路径完全相同，路径集 SHA256 为 `e6679c18a985b4dbd8cea43094cc26a7270831b6768f53dc7c89b5863ca19058`；生成器也保持同字节。登记清单仍为 1,279 项，SHA256 `d44dc342ab665b9abfeaf85bafcdb3a115069f45c80ad0fe09a8d6fe3d747b92`。已有 C7 的只读 render 与该清单相等。

因此，这个既有路径内的内容变更不需要新增登记；之后真正编译时 `include_bytes!` 会读取新的 History 字节。这里没有在新树的工作树上执行 `--check`，也没有编译新树。静态无冲突和清单结构一致，均不等于新 source 的运行资格。旧 C7 ELF 不能借用 base91 的源码身份。

## 原件与发布边界

`raw-review.original.json`、`isolated-canonical-review.original.json` 和 `inventory-static-consistency.original.json` 保留三次只读检查的实际结果。`raw-output-index.json` 把每个原路径、字节数与 SHA256 对应到 `raw-logs.tar.gz` 的唯一成员；18 条 Git 命令的 stdout/stderr 均核对原 pin，归档后逐成员读回。已执行的三段审阅脚本与 authoritative job terminal 另行保留。

本包没有 ELF、SQLite、state 目录、进程环境转储或凭据。`manifest.json` 是磁盘与归档成员核验，不声称已进入 Git index 或 published commit；发布者须对明列成员完成 force-add 与 index／commit 字节读回。文档是事后证据整理，不能改变源 C7、原试验声明、CI event tuple 或四门 HOLD 状态。
