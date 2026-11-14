# R1 三个历史 budget 控制失败：输入匹配结论

## 实际结果

三个 job 的原报告都为 FAIL，唯一错误为 `IDENTICAL_GROUP_TESTS_LOCK_AND_PROFILE_REQUIRED`。它们都只完成 driver/subject 的两个 source preflight（均 exit 0），随后在编译前停止：native 进程数为 0，cases 与 executables 为空，matched failure/pass control 均为 0。每个 job 的 43 个 Python runner 拒绝控制通过；这是 reader 自身控制，不能代替未启动的 native 反例。

| 模式 | job | artifact | 被测历史 subject |
|---|---:|---:|---|
| pool-scan-before | 132475258169 | 14117367614 | ae657e262278ae4a058220f66a6a0495721eb9ad |
| budget-before-v2 | 132475258063 | 14117727292 | 89fb2269b0dd306fbd32c36f464842c3d7daee2b |
| pool-before-v2 | 132475257835 | 14118225390 | 84e68b4f7a9b2f48f9c47ed05c9a44229d186e30 |

workflow/run 为 R1 / 43604217513 / attempt 1；实际 driver 是 R1 commit 2a86462a1ab20c68151719ba4635e3c294391e64，tree 5c26776f96f15fd131e85a5c2d7c5e895ad7fab4。两份 checkout 的 before/after 原始身份逐字相同。三个 ZIP 都按原 API size/digest 全量核验；各 14 member 全 CRC/SHA 核验，未执行任何包内内容。

## 首个不等项与后续独立差异

检查顺序由 runner 第 144–147、680–687 行确定。三个 subject 的 `trillionnium/Cargo.toml` 都与 R1 相同，下一项 `trillionnium/Cargo.lock` 已不同，因此实际首先拒绝的是 lockfile。原 report 没有打印具体路径；这里由原代码顺序和固定 Git blob 比对推导，未伪称原日志已经输出路径。

| 输入 | 历史 blob | R1 blob | 结论 |
|---|---|---|---|
| Cargo.lock | def80fa394ebb1ae6ce7d1d62ed77524152a2d04 | 19530b3bce6b679ae87cb5b92b0578faf781c0b3 | 三组均不同 |
| Node Cargo.toml | f03902e8ee3d081e3ffc9d965be4fdd3b5786c5f | 140b9af87ebf85d3e05e525c638dc9c65b965a5e | 三组均不同 |
| History budget fixture | 0c910637bb3644968adfc59d1a96724402c0530e | cf02b6c7426626c0bd56a91e0ff515dc6053083c | budget 组不同 |

Node manifest 中 rustix 1.1.4→1.1.6、rusqlite =0.41.0→=0.41.1，并增加 getrandom =0.2.17 dev dependency。完整 lockfile 还包括密码学、SQLite、serde、clap 等依赖图变化。这些不是格式差异。workspace manifest 与 rust-toolchain 逐字相同，只能证明这两个输入保持，不能消除依赖图差异。

pool-scan 的 pool_reconcile_control_tests、pool 的 pool_run_control_tests、budget 的 mining_prepare_control_tests 均逐字相同。History fixture 则有明确阶段变化：旧版在 M06 前注入债务；当前正控在 admitted/native commit 后为 successor 续期，同时保留一个 native completion 前必须拒绝的新负控。当前 cancellation/deadline 保留第一个已提交 packet，cold reopen 可激活它。不能将这两个 fixture 视为等价。

## 守卫原意与当前接缝

runner 开头声明旧/current 采用相同 group test bytes，且任意非零退出不能算反例。第 611–618 行严格固定历史 subject 与 fixed=current driver，第 680–687 行落实完整输入同字节。第 896–912 行的原 Python 两个负控明确要求输入变化后不编译、不启动 native。

另一方面，runner 第 362–377、422–439 行已经分别验证旧 History schema v2 与当前 native-completion v3 的不同阶段语义，却仍要求整份对应 test 文件相同。因此它存在当前 CI 比较合同未同步的问题：只调整 lockfile，budget 模式仍会在真实 fixture 差异处拒绝。

43 个 reader tests 使用合成的 identical reader fixture（第 760–787 行），所以它们成功并未证明固定旧 subject 与当前 driver 的真实输入相等。

## 保留强度的修复方向（尚未实施）

1. 先完善失败诊断：在现有 require 之前记录当前比较的 path、subject/driver bytes/SHA，并保留已经比较的输入。拒绝条件与 native-zero 语义完全保留。
2. 明确保留的旧实验使用独立审阅、不可变的 fixture/lock/profile 绑定。如果要继续声称 before/after 对照，还须找到并验证真实匹配的 reference source 与实际结果；本次没有选择或验证该 reference。当前 fixed arm 继续绑定当前 driver，并独立报告当前 native-completion 合同。
3. 如果任务要求重新证明 R1 同条件 before/after，则应另建明确新 subject/commit/tree，固定当前测试、依赖与 profile，只改变待验证的生产差异，再取得原 native 结果。这属于新的实现/执行工作，本次未做。

不能删除 guard、将 native0 重标成预期失败通过、悄悄覆盖旧 subject/test、只改旧 schema/digest，或回退当前依赖来消除报错。当前三项应记为实验输入不匹配导致的 CI 编排失败，不是已执行的性能失败或成功反例。

## 证据范围

机器账本 `review.json` 引用原 acquisition summary、三份完整 ZIP/index、原日志、source receipts、每个 source path 的 Git blob 和完整差异；`EVIDENCE_INDEX.json` 冻结本轮外部材料。此次仅只读原件与 Git 对象、写外部审阅说明；没有网络重试、源码/refs/stage 修改或 native/test 执行。
