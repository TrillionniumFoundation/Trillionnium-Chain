# Hepta / Chain 实际身份读回与 prepare-bound 工程预检

## 实际结果

本证据保留一个真实拒绝、一个新的正向工程预检，以及同一真实源码与运行时下的跨 reader 一致性检查。没有新增训练、模型 forward、真人授权、付款、奖励或科学资格。所有新参与者与 native 同意回执均为明确标记的工程模拟。

1. **真实 runtime / projection 一致。** 在实际 `/tmp/hepta-bound-loop-runtime-20261124/bin/python` 中，Hepta `paired_loop.implementation()` 与 Chain 对实际复制的 150 个 `.py` 文件调用 `runtime_identity(source_files(snapshot))` 的结果完全一致。实现摘要为 `96c766d74cc3973255e2068b8079d7058ef0f54f509e480601b7e0e089e1a426`。旧 consumer 原归档中的 release、admission、request、freeze 的投影也通过双方真实 reader；这只检查读回一致性，不重新授予旧记录任何权限。
2. **旧 consumer fixture 保持拒绝。** 对原 `CONSUMER_ENGINEERING_ORIGINALS.zip` 直接运行真实 `prepare-bound`，子进程退出 1，复现脚本退出 2。其 freeze `57c67abb…` 在原归档和原发布 commit `0cf29b6a…` 中均没有匹配 catalog，所以在 catalog 检查处停止；ADMISSION、RESERVATION 都不存在。未补造 catalog，也未把失败改记为成功。独立 `unshare -Urn` 环境探针退出 0，故这个拒绝由缺失材料导致，不是隔离环境不支持。
3. **新的 engineering admission 通过真实正向门。** 使用另一组已有权重（freeze `447ace5c…`、candidate `6a094252…`）及它早已登记的完整原 catalog，先封存原 catalog 与原 source/plan/training 的指纹，再建立独立的新 study、journal、模拟 native executable 和模拟 B 到达。经原 `paired_observation`、`paired_intake.install`、真实 `paired_intake admit` CLI 和 `release` 接口生成新的 binding。随后真实 Chain `prepare-bound` CLI 以原 `unshare -Urn` 隔离预检退出 0，产生 v2 ADMISSION；实际 `check_terms(live=True)`、loop pin、源码 pin 均通过，RESERVATION 不存在。

## 正向 run 的身份

| 字段 | 精确值 |
| --- | --- |
| 新 study | `21fecc00d1e7f3367807cf00bd137967d318b835dd86174e9f78c5710db15692` |
| 新 Hepta admission | `795ca21dec4bb40a063598213f494260c6464b574ff6fc6e1e3e6374f3b52b14` |
| 新 paired request | `a21273dc65f86a86723fdb14842848e798db5427b40fc6b32d74102e09aeab6b` |
| 完整 loop identity | `f5c315890b961887638a9f6a06b68ed64d03e52e73850142dfab554b569144f4` |
| Chain ADMISSION 文件 SHA-256 | `7fd3f98a0fe2249d31ccc02f041b1489b2fc3075ade15b744e27cab03e289800` |
| 原 catalog 文件 SHA-256 | `622c3b0d23d45ca2212345d666faa5ca3b7705e08a1f0a546b2a96f80449ce9c` |

原 catalog 字节未修改。记录中的历史 prompt 指纹、公开源 revision/row/file 指纹、训练计划、保留任务与该 catalog 对应；两套已有 tokenizer 对旧 rehearsal / retention 的四项 token 指纹实测一致。历史完整 Parquet **本次没有重读**；没有声称重新验证其内容。新 study 的摘要绑定预到达 registration，然后才创建新的模拟 B 记录。真实用户的时间、授权或独立性不由这些工程事件建立。

实际运行时为 Python 3.12.14，torch 2.9.1+cpu、transformers 4.57.3、peft 0.18.0、tokenizers 0.22.2、safetensors 0.7.0。源码与 Python executable 的逐字节摘要已记录；第三方包仍为安装版本身份，`runtime_closure_complete=false`。

## 原件与复现

`MANIFEST.json` 给出完整压缩包或全部分片的 SHA-256、大小、重组次序和包内逐文件清单的摘要。压缩包内 `FILE_SHA256.json` 覆盖每份保留原件的字节长度与 SHA-256；`EXECUTION.json` 保留原命令、外层及真实 CLI 退出码、源码 commit 与复现脚本摘要。`runtime-and-projection.json` 保留实际跨 reader 读回。`blocked-originals/` 完整保留失败请求、物料、源码快照、日志及后续只读查证；`fresh-engineering/` 完整保留新 journal、模拟 native 原件、预到达 registration、模型物料、日志、实际 v2 ADMISSION 与源码快照。

使用与记录兼容的实际 Python 环境、完整 Hepta checkout 和 Chain checkout；每次指定两个尚不存在的新目录：

```sh
PYTHONDONTWRITEBYTECODE=1 /path/to/runtime/bin/python -B check_bound_prepare_originals.py /path/to/hepta /path/to/chain /new/blocked-output
PYTHONDONTWRITEBYTECODE=1 /path/to/runtime/bin/python -B check_bound_prepare_fresh_engineering.py /path/to/hepta /path/to/chain /new/engineering-output
```

第一个脚本应保留原样拒绝；第二个会生成新的、明确模拟的 study/admission，所以 nonce 及其派生摘要会变化。它从原 source catalog 与权重重新检查后，再运行实际隔离 CLI，没有 mock 掉 `unshare`、预检或 v2 条款验证。两脚本都不调用训练函数、预测函数或 ledger reservation。

## 资格边界

新工程 admission 没有重用或重新包装旧 consumer / paid v1 授权。旧付款读回保持原 v1 身份；其已有 12 份模型物料和 catalog 的只读逐项核对也保存在失败侧的查证材料中。这里证明实际源码及运行时下 v2 准备流程可以接通，不证明能力改善、独立用户采用、生产 PoUW 或真实支付。

`BOUND_PAIRED` 的 native paid ignored 测试仍是独立工程门，**本证据未运行该门，也未建立新付款**。后续真正 A→B 闭环仍须原站点的真实入组、原授权、预到达冻结及再次采用材料。
