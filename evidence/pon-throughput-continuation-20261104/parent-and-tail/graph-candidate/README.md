# Parent graph continuation through native INSERTs — HOLD

**本候选仅作为可重现的实验归档，不默认启用。** 十个专属源码路径恢复到共同基底 `b8116f65789a85148254f870c678a44f895316de`：七个既存文件恢复原始字节，三个新增文件删除。实际逐文件恢复结果记录于 [restoration.json](restoration.json)。独立的 DirectAppend、TCP 和 M06 工作不属于本次恢复集合。

[decision.json](decision.json) 固定保守决策；[cost-readback.json](cost-readback.json) 从全部既存原始样本重新核对描述统计。整理本包没有构建或运行任何原生测试，也没有修改接受规则、增加状态大小阈值、跨 COMMIT 复用证明或降低 Host 检查。

## 为什么保留实验而不启用

候选先在同一原始 WRITE 事务内完整验证父账户图，再尝试用实际成功的闭合 INSERT 及读回延续其有限证明。初始 schema RESET、父图完整检查、实际写入行数、实际行字节、每次写 epoch 连续性和最终 schema/owner 检查仍存在。原始完整发布流程作为独立对照保留；任何未满足延续条件的情况返回原完整验证路径。

这些检查尚不能独立证明数据库物理 B-tree 页的所有权及互不重叠。独立 fresh in-memory DDL 生成的精确 catalog（包括 rootpage）可以作为更窄的可选资格条件，但它本身不等同于内部页所有权证明。合法既有库、VACUUM 或布局差异也可能不符合该资格，应保持原完整路径，而不是变成新的 Node 错误。**本轮没有复现绕过或已确认漏洞；未进行跨表物理页破坏演示。** 安全论证尚未完成，不能靠样本通过来补足。

性能上，移除新增的逐 INSERT 完整 catalog 检查后，68 个真实账户的 changed-state 样本仍有 **10.79% CPU 回退**。大状态样本的改善不能抵消这一负面观察，也没有据此挑选启停阈值。因此，本轮保留全部候选和失败证据，恢复共同基底的默认发布及 SQLite scope API。

## 三种源码身份

| 归档 | 基底与身份 | 实际运行范围 |
|---|---|---|
| 第一版 f56/dd6a | dirty `73ab6e9a83bcc836e261d93f9bb23ceafe556758`；native map `f56cc35bd9c9462c931776cc4e08fedeeaa7c73df5f00b2907cc2a057bc81381`；ELF `dd6a1dee07568ba26022ccd690933af13788696e1925e442fe3ba471927f856f` | post-write 模块 34 passed / 0 failed / 1 ignored；独立 paired-cost 1 passed |
| 最后实测 0e9d/65d2 | 同一 dirty 73ab 基底；native map `0e9dd2812f4ae9388e5bba175934ee71632c4e053f5f94906d0dd21a22209c88`；ELF `65d283d519c942230a44b99db1b05308f226d5bca9706f8a1db059a7b852e144` | post-write 模块 35 passed / 0 failed / 1 ignored；独立 paired-cost 1 passed |
| b811 上合成的候选 | `b8116f65789a85148254f870c678a44f895316de` 加本候选十路径 patch | **未执行新的 native 构建或测试**；不能标记为 0e9d 的实测结果 |

两个历史 native map 各包含 1,194 个记录输入。原始 before/after 及 ELF 哈希均保留。本包未复制约 392 MB 的二进制；实际 ELF 身份、大小和构建命令在原始记录中。它不声称全部仓库或并行文档被冻结。

三份仅含本候选十个路径的独立 patch：

- [第一版相对 73ab](source/f56-owned-from-73ab.patch.gz)，[逐文件身份](source/f56-owned-from-73ab.json)。
- [最后实测版相对 73ab](source/0e9d-owned-from-73ab.patch.gz)，[逐文件身份](source/0e9d-owned-from-73ab.json)。
- [未实测合成版相对 b811](source/untested-composition-from-b811.patch.gz)，[逐文件身份](source/untested-composition-from-b811.json)。

每份 patch 均在一次性 scratch 树内从相应 base 应用，并与捕获的十个目标文件逐字节核对：[patch-verification.json](source/patch-verification.json)。**这三份局部 patch 本身不重建完整历史实测 ELF。** 完整 f56 的十八文件 native patch、所有输入 map 与首次失败恢复 delta 见 [TCP 历史包](../tcp/README.md)；0e9d 的十九文件完整状态由该 patch 加 [trimmed-schema overlay](../tcp/trimmed-schema/README.md) 重建。不要把其他协作改动从实测身份中删掉。

## 原始控制和失败

| 观测 | 原始记录 |
|---|---|
| 首次完整 Node 编译失败：三个 E0425，测试 helper 缺少 ensure 导入；exit 101，未运行测试 | [build-result](failures/build/build-result.json)、[cargo stdout](failures/build/build.stdout.gz)、[stderr](failures/build/build.stderr)、[源清单](failures/build/source-before.json.gz) |
| 首次 launcher 失败：直接执行无执行位 wrapper；没有启动原生测试，exit 为 null | [result](failures/launcher/result.json)、[command](failures/launcher/command.json)、[原 harness](failures/launcher/run-controls.py) |
| f56 完整 Node 编译成功 | [build-result](f56/build/build-result.json)、[cargo stdout](f56/build/build.stdout.gz)、[stderr](f56/build/build.stderr)、[编译环境](f56/build/compiler-environment.stdout) |
| f56 post-write 模块及配对成本 | [模块 stdout](f56/controls/stdout.txt)、[模块 result](f56/controls/result.json)、[cost stdout](f56/cost/stdout.txt)、[cost exact reader](f56/cost/required-test.json) |
| 0e9d 完整 Node 编译成功，原 profile、all-features、no-run | [command](0e9d/build/command.json)、[result](0e9d/build/result.json)、[cargo stdout](0e9d/build/stdout.txt.gz)、[stderr](0e9d/build/stderr.txt) |
| 0e9d post-write 模块及配对成本 | [模块 stdout](0e9d/controls/stdout.txt)、[模块 result](0e9d/controls/result.json)、[cost stdout](0e9d/cost/stdout.txt)、[cost exact reader](0e9d/cost/required-test.json) |

最后实测的 [registry](0e9d/controls/registry.txt.gz) 包含 pre-write 的完整 **13 个 selector：12 ordinary + 1 ignored cost**；[candidate-selectors.json](candidate-selectors.json) 保留精确全名。控制覆盖实际发布、仅工作状态变更、重复 INSERT、无行写、delete/restore、事务 ABA、实际图损坏、trigger、旧 prepared VM/catalog、prepare-only RESET、最终只读配置及 attached DB 漂移、取消和 SQL 等价。

本候选新增的 **9 个 known-write scope 测试源码完整保留**。先前会话曾观察 22 项控制输出，但未找到完整、持久、绑定精确 source/ELF 的原始收据；随后两处显式 drop 又改为词法作用域。因此，这份归档的最终九项 boundary 控制执行资格是 **null / 未确立**，不标成 PASS，也不拿旧十三项日志替代。本包的 Node 历史结果与此范围分开。

## 两次配对成本：保留所有样本

对照是测试内保留的原始完整 publication 流程，候选是相同输入上的新 continuation 流程；不是两套不同提交的完整 Node 二进制。每个输入先各臂 warmup 一次，再按 **ABBA、BAAB、ABBA** 三组运行，每臂六个计时样本。这里用六项的 lower median 描述结果，不作 p95/p99 或服务准入结论。

| 真实账户数 | 输入变更 | 第一版对照 → 候选 CPU ms | 第一版变化 | 最后实测对照 → 候选 CPU ms | 最后实测变化 |
|---:|---|---:|---:|---:|---:|
| 68 | 仅工作状态 | 4.815061 → 4.503657 | −6.47% | 3.979406 → 3.543857 | −10.95% |
| 68 | 真实转账 | 5.868209 → 7.957110 | **+35.60%** | 4.648422 → 5.149859 | **+10.79%** |
| 1,028 | 仅工作状态 | 30.917453 → 21.398808 | −30.79% | 25.370513 → 17.474534 | −31.12% |
| 1,028 | 真实转账 | 25.664611 → 23.492646 | −8.46% | 25.324404 → 20.006194 | −21.00% |

[第一版完整 JSONL](f56/cost/cost.jsonl) 的 SHA256 为 `00ec88a443c3ea22e346b64b78e013a4cd638596a0a44dbf1a5f3f2dbdad9466`；[最后实测完整 JSONL](0e9d/cost/cost.jsonl) 为 `873ec5f8b484b5189087b025ecc5233304a885ea7ac1b595d8ce106d3d993067`。每轮共 56 个样本（含 warmup），实际 SQL 字节比较全部相同。两轮分别统计，不把它们当成跨版本同一计时配对。

这些是 debug libtest 的实际 publish 组件观测：包括资格判断、完整父图、当前 State commitments、固定 SQL INSERT 和实际读回、child/history 验证及最终 writer/schema 检查。真实签名 fixture 的生成和先前 admit/W1 成本另记。计时调用**不包括独立 W1 replay、实际 Host admission、ingress、COMMIT、网络或独立客户端确认**，也不包括 fixture 回滚清理。完整 SQL 表字节比较在计时区间外进行。不得据此宣称四秒 SLO、吞吐量、PQ/WAN、低配 Host 或整体业务门槛闭合。

## 完整性和人工复现

在本目录执行 `sha256sum --check SHA256SUMS`，即可核对归档内容。[copy-verification.json](copy-verification.json) 同时保存所有原始 payload 与存储文件 SHA；gzip 解压后的字节与原始日志完全相同，空 stderr 也保留。

原始 harness 保留观测时的绝对路径，只作 provenance。未来复现应先按 [完整历史重建说明](../tcp/trimmed-schema/README.md) 在独立 checkout 中恢复正确的 dirty 73ab 原生输入，逐项核对 1,194 输入，再运行 preflight 和原 all-features 构建命令；不把实验 patch 应用到正常候选。构建后记录新 ELF 哈希，不假定不同路径重建后的 ELF 字节相同。

得到该独立 test ELF 后，模块调用保留原参数：

```bash
"$graph_node_binary" store::native_authenticated::post_write_readback --nocapture --format pretty --test-threads=1
```

cost 必须单独执行，输出必须使用不存在的新文件；不得覆盖历史负面数据：

```bash
graph_selector='store::native_authenticated::post_write_readback::tests::frontier::pre_write::native_publish_continuation_paired_real_sql_cost_observation'
TRNM_NATIVE_PUBLISH_CONTINUATION_COST_OUTPUT="$graph_new_cost_path" "$graph_node_binary" "$graph_selector" --exact --ignored --nocapture --format pretty --test-threads=1 > "$graph_new_stdout" 2> "$graph_new_stderr"
python3 scripts/ci/check_required_native_test.py "$graph_new_stdout" --test "$graph_selector"
```

以上命令仅作为未来人工复现说明；本次归档没有执行它们。恢复默认实现也不构成恢复后源码的 native 验证结果，后续组合版本仍须执行自身的完整 gates。
