# selected-event 实际哈希组合与可计价模型：重建验证版

这是旧本地目录丢失后的**重建版**。原始 selected-event Python/Rust 源、旧 fixture 和原 native 观测已从保存的 round-1 bundle 恢复；组合模块、证明、计价说明和测试从保留上下文重建。**本目录使用新的源码 SHA、新的运行日志和新的校验清单，不沿用丢失 round-2 文件的旧 SHA 或旧测试结论。** 详细来源在 `RECOVERY.md` 与 `provenance.json`。

本次实际运行于 **2026-11-07 23:17:55 UTC** 完成：**21 项检查全部通过**，测试数量直接从本次 unittest 输出读取。原 native 观测只作历史对照，本次没有运行新的 native benchmark。资格保持 **HOLD_NO_GO**。

## 已交付的具体结果

### 1. 真实域分离链的经典 ROM 组合证明

`THEOREM.md` 包含实际编码、Merkle、task、context、noise-seed、selector、noise、event、ticket 的完整论证。它对实际两层 `H_ticket(H_event(canonical))` 显式补入“先查询猜定 digest，后来补出前像”的概率预算。

令 `q=4294967291`、`beta=1-(1-q^-8)^4`、`K=min(M,floor(H/32))`，在文档规定的终身预算、目标和反馈模型下：

\[
\Pr[W\ge t]\le\Pr[\operatorname{Bin}(K,p)\ge t]+32MR\beta+\varepsilon_{\rm hash}.
\]

哈希误差项覆盖全域输出碰撞和所有五类反向引用：Merkle→node/task、task→context、context→seed/event、seed→selector/noise、event→ticket。所有预处理、被筛掉的候选、保留状态和 verifier completion 都进相应全局预算；验证者的 noise 工作不能回填为矿工 H。

证明明确处理了自适应失败反馈、首次正确猜测前的集合覆盖、拒绝采样独立性、包含未中奖正确候选的 paid-first 序列和无条件 stopping argument。完整 row 的辅助揭示仅用于分析，原始 ROM 的 fresh-output hazard 不被改写。它是**条件经典 full-message ROM 查询界**，不是具体 SHA、QROM、STARK、生产权限或普遍物理成本证明。

### 2. 可执行的合法 SHA 前缀复用

重建的 `sha256_prefix.py` 逐个摘要与 `hashlib` 核对。相同 seed 的 32 个 noise digests 可共享首块状态，把 **64 次普通压缩降为 33 次**。

对于固定 task/context、准备好 Merkle 树的完整 producer（包含 event 与 ticket），本次结果是：

| 阶段 | 普通完整调用压缩数 | 缓存完整摘要 | 有界前缀缓存 |
|---|---:|---:|---:|
| 两棵 Merkle 树准备 | 1,146 | 1,146 | **894** |
| 首个 nonce | 96 | 88 | **57** |
| 第二个 nonce | 96 | 80 | **47** |
| 第三个 nonce | 96 | 80 | **47** |

有界实现最多保存 5 个首块状态、2 个完整摘要，当前 key/state 逻辑 payload 为 **981 字节**。它会淘汰旧 noise seed/context，不依赖无限历史缓存；另外保留完整 prefix trie 作诊断对照。100 个 seed、800 条消息的淘汰核验也在本次检查中通过。

这些是实现出来的资源上界。压缩数减少并不自动证明程序更快，缓存、比较、内存及准备成本必须另计。也不能把“32 行查询界”错误地换成“至少 64 次实际 SHA 压缩”。

### 3. useful-product 缓存与算术摊销

两种 producer 使用相同的树准备策略，分别直接算 U 和缓存全部 512 个 U。后者预付 **262,144 次乘法、229,376 次加法、131,072 字节表**，后续每 nonce 从 **2,048 次乘法降到 1,536 次**。仅按同算法的乘法/加法成本，512 个 nonce 持平，之后才有节省；正的内存与读取价格可能延后或消除优势。

`PRICING.md` 列出完整输入字节、sampler 重试、普通 SHA 调用与 compression 的区别、Strassen 深度的精确可达算术计数、缓存准备和跨 nonce/context 摊销。零/低秩/重复块、批量算法可能仍更便宜，所列策略没有被冒充成全局最优。

### 4. 从真实旧 fixture 重新核验

恢复的三个旧 fixture 在本次 Python 回放中重新匹配原 native 计数与结果：

| Fixture | 结果 | SHA calls / bytes / compressions | 标量乘法 |
|---|---|---|---:|
| real_lottery_hit_p_1_64 | 接受 selected event | 56 / 8,128 / 152 | 2,048 |
| false_noisy_product_0 | NOISY_PRODUCT | 54 / 7,691 / 144 | 1,536 |
| false_useful_product_0 | USEFUL_PRODUCT | 54 / 7,691 / 144 | 2,048 |

两种 producer 各测试 nonce 24、25、26；witness 均与未改动的原参考实现相同，event/ticket 也一致。没有重造历史 fixture、生成新的 target-qualified false claims，或把历史 native 时间当成本次测量。

## 可配置的精确预算

`composition_budget.py` 使用 `Fraction`，输出完整有理数。三个 `budget_example_*.json` 声明假设的 M/R/H 及各 domain 终身查询上限，包含最多 1,024 次 verifier completion。这些是输入假设，不是从成功样本反推出来的矿工能力限制。

p=1/64、M=2^32、R=2^16 的示例：

| 项目 | 44 次 paid-trial 容量 | 45 次容量 |
|---|---:|---:|
| H 行访问预算 | 1,408 | 1,440 |
| 纯彩票至少一中概率 | 0.499890250976003… | 0.507704465804503… |
| delta | 3.111507667909×10^-61 | 同左 |
| epsilon_hash | 2.052777300179×10^-48 | 同左 |

因此在这组预算下，44 次容量加误差仍不足 1/2 成功；至少需要 1,440 行访问预算才可能达到该概率。该句不等于 1,440 个物理哈希或某个微秒成本。另一个 M=R=2^64 压力示例给出 delta≈3.76158×10^-37、epsilon≈6.75909×10^-38。M×R 是宽松预算乘积，总 event 查询数另有限制，并非每个候选都实际发出了 R 次猜测。

十进制展示只有 24 位，极小误差可能在展示中不可见；精确分子/分母始终保留。过长整数明确用 `integer_encoding: hex` 表示。

## 复现

需要 Python 3.10+ 及标准库；本次使用 Python 3.12.14。进入本目录执行：

```bash
python3 -B run_checks.py
```

该命令重新执行测试、成本实验及三个预算，写出本目录的日志和 JSON。它会从实际 unittest 输出统计测试数。若 `provenance.json` 记录的恢复来源仍存在，会只读检查旧 `work_bound` 的 9 个实际文件未变；在独立下载的 GitHub package 中路径不存在时，会明确记录该情况，不妨碍自包含验证。

也可分别执行：

```bash
python3 -B -m unittest -v test_composition
python3 -B exact_cost.py
python3 -B composition_budget.py budget_example_45.json --output my_budget_result.json
```

精确 binomial 实现限制 K≤10,000，以控制整数增长。更大的预算需使用文档中的符号式或另行实现严格数值界，程序不会悄悄改用浮点近似。

全部必需 source/fixture 已随 `reference/` 提供，不需要 Cargo、网络或原 workspace。复制的两份 Rust 文件用于审查实际 domain/encoding 调用，不是一个完整 crate；本目录不声称重新编译或运行它们。

## 文件地图

| 文件 | 内容 |
|---|---|
| THEOREM.md | 完整组合定理、预算、证明与一手来源 |
| PRICING.md | 精确哈希/算术/缓存计价与边界 |
| RECOVERY.md | 恢复链、原样恢复与重建区分、历史/新证据边界 |
| composition_budget.py | 精确概率与有理数价格 |
| exact_cost.py | 原参考计数、prepared producer、旧 native 观测回放 |
| sha256_prefix.py | 独立 SHA compression、完整 trie 和有界缓存 |
| transcript_audit.py | typed pointer 与输出碰撞账本 |
| test_composition.py / run_checks.py | 本次可执行检查及重跑入口 |
| reference/ | 原始源、真实旧 fixture 与旧观测字段 |
| provenance.json | 所恢复原件的 SHA 与旧档案核对基线 |
| checks_summary.json / unit-tests.log | 本次实际运行记录及新源码 SHA |
| exact_cost_results.json | 本次逐样本计数和 cache payload |
| budget_example_*.json / budget_result_*.json | 模型输入与本次精确输出 |
| SHA256SUMS | 本重建版交付文件的新校验和 |

重新运行会更新日志与 summary 时间戳，届时应生成新的校验清单。发布研究分支时应包含实际源和 binary fixture，而不是旧结论摘要或丢失版本的 SHA。**本轮没有生产接入、资格提升、合并或上线；HOLD_NO_GO 保持不变。**
