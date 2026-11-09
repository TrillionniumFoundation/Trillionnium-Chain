# P1：CDHZ 最新 QROM 原文的定点复核

观察日期：2026-11-09。范围仅为 ePrint **2025/2166** 的最新文本、既有 January→March 比较证据及其 W1 适用边界。冻结的代码、profile、contract 和资格字段均未修改。

**结论：官方元数据仍指向 2026-03-02；本轮未重新取得两份 PDF。但 Git 中确有 2026-11-08 的完整版本比较产物，已经读取并通过 13/13 项内部一致性核对。既有正面比较证据应保留；本轮未独立复算 PDF 文本或渲染，不能把这一复核写成新完成的原文版本等价验证。完整 W1 安全结论继续 HOLD。**

## 1. 本轮实际访问了什么

论文为 Alessandro Chiesa、Zijing Di、Zihan Hu、Yuxi Zheng 的 *How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions*。下表中的访问结果属于本轮观察，访问失败也保留。

| 主来源／入口 | 本轮结果 | 能确认的范围 |
|---|---|---|
| [ePrint 正式条目](https://eprint.iacr.org/2025/2166) | 正常读取；最新修订日期为 2026-03-02；另标 EUROCRYPT 2026 出版信息 | 论文身份与最新元数据；不是全文 |
| [ePrint 版本历史](https://eprint.iacr.org/archive/versions/2025/2166) | Web 读取 HTTP 403 | 本轮未重读完整版本列表 |
| [最新 PDF](https://eprint.iacr.org/2025/2166.pdf) | 从正式条目跟随 PDF 链接，HTTP 403 | 未取得原件 |
| [March 冻结 PDF](https://eprint.iacr.org/archive/2025/2166/1772467621.pdf) | Web 工具报告不可访问；随后一次普通无凭据 GET 明确返回 HTTP 403 | 未取得原件；未修改请求身份或访问控制 |
| [January 冻结 PDF](https://eprint.iacr.org/archive/2025/2166/1767247987.pdf) | 与上项相同 | 未取得原件 |
| [EPFL 机构条目](https://infoscience.epfl.ch/entities/publication/029a1aad-a83a-4e7a-bbf7-03819bb7dd4b) | 正常读取；页面未提供可跟随的开放全文链接 | DOI、作者、会议及页码 389–415；2026-06-18 是条目可用日期，不是 ePrint 新修订日期 |
| [Springer 正式章节](https://link.springer.com/chapter/10.1007/978-3-032-25336-1_14) | 正常读取摘要、注释与文献；明确为订阅内容预览 | 出版章节为 27 页，First Online 为 2026-05-09；本轮不能把它等同于 102 页 ePrint 全文 |
| [Zihan Hu 主页](https://zihanhu.cn/)、[Zijing Di 主页](https://dizidizidi.github.io/)、[Alessandro Chiesa 主页](https://ic-people.epfl.ch/~achiesa/) | 正常读取；论文链接回到 ePrint | 未找到独立的最新全文镜像 |
| [作者的 pq-bcs.pdf](https://zihanhu.cn/assets/pdf/pq-bcs.pdf) | 作者主页明确标记为 slides；Web 工具另因 13,802,289 字节上限拒绝读取 | 不能用演示材料替代论文；没有将工具长度错误记成站点 403 |
| [Yuxi Zheng 主页](https://yuxi-zheng.github.io/) | 正常读取；未提供该论文全文链接 | 没有新增全文来源 |

精确标题检索还发现 CORE 聚合副本，其检索文本显示 **January 1, 2026**。该结果没有被当作作者／机构提供的 March 最新原件，也没有据此建立版本等价。普通公开来源检索到此停止；本轮没有联系作者、购买章节、登录机构账号或绕过访问限制。

两次普通 GET 的原始状态记录见 [official-fetch-attempt01.json](qrom-followup-inputs/official-fetch-attempt01.json)。其他入口与检索来源记录见 [qrom-latest-followup-sources.json](qrom-latest-followup-sources.json)。

## 2. 找到了可审计的既有比较产物

只检查 sparse 工作树会遗漏原证据。对源提交 `e4e4a8e049915ba09d9e97444b4709ce8769ce81` 执行完整 `git ls-tree -r` 后，发现：

```text
evidence/pon-w1-qrom-proof-chain-20261108/manuscript-comparison.json
Git blob: 4019abb76cf7805854fcac477650022a1eacba9a
Bytes: 74335
SHA-256: 5c0d265707758448d263aa3c02788a9f13025e0644143024596e07a03940279f
```

通过 `git show` 精确读取该对象，保存在 [tracked-manuscript-comparison.json](qrom-followup-inputs/tracked-manuscript-comparison.json)。这不是新生成的 PDF 比较，记录的观察日期仍为 **2026-11-08**。同一 Git tree 没有 `.pdf` 路径；限定相关 PDF 文件名的 scratch 搜索也未找到原件。这里的“未找到”限于所记录树与文件名范围，不外推为历史上从未取得原件。

该产物固定的输入身份与仓库比较器 `scripts/w1_cdhz_revision_compare.py` 完全一致：

| 输入 | January | March |
|---|---|---|
| 修订 ID | `20260101:061307` | `20260302:160701` |
| PDF 大小 | 927,381 B | 927,435 B |
| PDF 页数 | 102 | 102 |
| PDF SHA-256 | `215a62b9a1b5144c89ae103aaabaf6049eab23f7ccb23130bc7d65d597c1eac9` | `2cfb88c76732d9f39f4b1943b4aabc0390dd3d17830d91d910c38e16e4bb5a30` |

本轮核对了完整 1–102 页清单、每页文本／RGB 摘要与 equality 标记的一致性、汇总的差异页、11 个定理起始页、两种 Poppler diff 的完整内容及其摘要、比较器的固定输入身份和声明范围；**13/13 项一致性谓词通过**，结果保存在 [tracked-comparison-review.json](qrom-followup-inputs/tracked-comparison-review.json)。这些是既有产物的结构与内容核对，不是 13 次原文重渲染，也不是密码学证明测试。

既有记录的文本和图像差异页都为 **1、4、100、101、102**；97 页相等，其中包含全部 5–99 页。完整 raw/layout diff 显示标题日期、引言引用键以及文献项和分页的变化，与 `docs/security/W1_QROM_MANUSCRIPT_REVIEW_20261108.md` 的叙述相符。该记录为“Jan→March 数学页未变”提供了实际可追溯的比较输出；本轮不能仅凭其哈希重新生成未取得的原始页。

因此，最终状态须同时保留两件事：**项目已有版本比较正面证据，本轮原件独立复取与复算未完成。** 不应把前者抹成“从未获取最新全文”，也不应把本轮读取既有 JSON 记录写成新的 PDF 等价证明。

## 3. Theorem 10.6、损失与 PCS／FRI：已有映射的精确边界

以下是对仓库既有原文审阅和实际固定 profile 的定点核对；论文页码、条件和推导来自该既有审阅，本轮没有再次逐页读取 PDF。它们构成后续复取原件时应核对的清单，不是本轮新增定理。

| 事项 | 仓库现有证据／映射 | 仍需守住的边界 |
|---|---|---|
| Theorem 10.6，pp. 72–73 | 既有比较将其起始页和证明所在数学页登记为相等；适用前提包括共同仿真 oracle `(Init,U1,U2)`、匹配的中间严格／放宽关系以及 Definition 10.3 的仿真、交换性、经典查询和直线提取条件 | 递归调用实际提取器与各组件误差函数尚须逐层映射；相同哈希名称或递归验证成功不能代替共同 oracle 假设 |
| 扩大的查询自变量 | `A=t+q_V1+q_V2+q_E2`；`B=t+q_V1`；`C=t+2q_V1+q_V2+q_E2+q_Rhat2+q_Rhat3` | 组件误差函数必须在这些扩大后的自变量上有效，不能仅在 `t` 点测量／定义 |
| Merkle online 误差 | 既有审阅将 Lemma 9.7 与 Lemma 8.8 合成为 `OnlineUpper(T,W_VC,sigma)=240 W_VC T² / 2^sigma` | 这里乘的是普通 VC 查询质量 `W_VC`，不是提取器查询质量；质量为非负实数，不能当作整数次数；误差度量是接受概率平方根之差的平方 |
| 原文参数顺序 | 既有审阅记录 Definition 7.3 与 Theorems 8.3/8.4 的 online 参数顺序不一致，并记录该问题在两版都存在 | 不可把 Theorem 11.3 的数值按位置机械代入较小误差；本轮没有取得作者勘误或确认 |
| Construction 11.11 的 `q_V` | 既有审阅指出 step 13 的 VC 检查查询已进入总查询 `T=t+1+q_V+k+d`，而印出的 ordinary VC mass 使用 `w_VC+d`；其保守本地 allowance 为 `w_VC+q_V+d` | 这是有明确出处的未闭合计量问题与本地上包络处理，不是作者勘误，更不等于完整 BCS 实例证明 |
| 实际所选 W1 | profile 固定 RISC Zero 3.0.6／Poseidon2／join-v2；BabyBear 模数 2013265921，扩域 4 次，FRI 查询 50、inverse rate 4、fold 16、终止参数 256 | P3 Goldilocks profile 和 native-pnw1 系统实验明确分开；其他 profile 的定理或预算不能借给此 profile |
| IOR／PCS／FRI 实例化 | 既有审阅要求实际 Node→guest→VM→AIR→全部递归的关系映射、RBR 知识状态函数与确定性多项式时间提取器、实际 VC 编码和盐、根／cap 结构、重复查询、sampler 与 FS 编码 | 单独的 FRI 参数或交互式误差不提供这些提取性质；还缺共享 primitive 的联合模型以及全部尝试和生命周期失败事件的联合预算 |

为避免把“数学页相等”误读为“损失可省略”，既有 Theorem 10.6 映射所计算的充分提取表达式是：

\[
2\operatorname{ext}_1(A)+2\operatorname{ext}_2(B)
+2q_{E_2}^{2}\left(q_{V_1}^{2}+
(q_{\widehat R_2}+q_{\widehat R_3})^{2}\right)
\min\{\operatorname{com}_1(C),\operatorname{com}_2(C)\}.
\]

此处仅用规范化的平方记号重述仓库映射，不声称本轮原文复核已完成。没有为实际 W1 补出任何缺失的 `ext`／`com` 输入，没有计算新的安全位数，也没有将八核 proving、60／300 秒 watchdog 或论文抽象预算代换原 Host 4 秒服务门槛。

## 4. 剩余动作与本次关闭范围

本次关闭的是“公开主来源定位、实际访问状态、被 sparse checkout 隐藏的既有比较产物和其内部闭合检查”。本次未关闭“原件重新获取后的独立版本复算”及“论文到实际 W1 的完整适用性”。

后续只需要精确补证，不需重做泛化文献研究：

1. 从正常公开主来源取得上述两份**精确字节身份**的 PDF；若字节身份变化，另立输入和结果，不能覆盖旧失败记录或沿用旧比较结论。
2. 对固定输入运行既有 `scripts/w1_cdhz_revision_compare.py`；保留原始 PDF 的来源、SHA-256、比较器源版本、工具版本、102 页完整结果及独立观察时间。若只取得出版方 27 页章节，应单独比较，不能自动认定它等同于 March 长文。
3. 将“Nov8 已登记版本桥”“本轮原件获取状态”“实际所选 profile 的定理映射状态”分开登记。任何未来资格字段更新都需单独审阅；这份 follow-up 没有改动 `latest_full_text_obtained=false`、`version_equivalence_verified=false` 或任何原始义务的状态。
4. 继续处理实际固定 profile 的提取器、共同 oracle、扩大查询域、online 参数命名与 `q_V` 计费、PCS／FRI 精确关系、全部失败事件和联合生命周期预算。即使重新完成版本比较，以上条件也不会自动成立。

源文件锚点：

- [既有原文审阅](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4e4a8e049915ba09d9e97444b4709ce8769ce81/docs/security/W1_QROM_MANUSCRIPT_REVIEW_20261108.md)，§§1–2、3.1–3.3、5–6。
- [固定字节比较器](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4e4a8e049915ba09d9e97444b4709ce8769ce81/scripts/w1_cdhz_revision_compare.py)，`EXPECTED`、全 102 页循环及 `whole_document_poppler_diffs`。
- [已有组合表达式 evaluator](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4e4a8e049915ba09d9e97444b4709ce8769ce81/scripts/w1_qrom_composition_budget.py)，仍引用 January 定理表达式。
- [冻结 profile](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4e4a8e049915ba09d9e97444b4709ce8769ce81/config/pon/pq-proof-profile-binding-v1.json)，`theorem_reference` 与独立 profile 排除项。
- [既有实现证明链审阅](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4e4a8e049915ba09d9e97444b4709ce8769ce81/docs/security/W1_QROM_PROOF_CHAIN_20261108.md)，继续声明完整 W1 HOLD。

上述对象的源提交、blob、大小和 SHA-256，以及本轮正常公开来源访问索引，统一登记于 [qrom-latest-followup-sources.json](qrom-latest-followup-sources.json)。本轮仅在 overlay 写入研究与取证产物，没有修改 repo、index、冻结代码或 profile，也没有运行 native benchmark。
