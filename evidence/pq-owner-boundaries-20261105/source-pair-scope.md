# S / R2 固定源码组合说明

**HOLD_NO_GO；activation = false；P0-1 严格退出条件未满足。** 本轮唯一候选源码组合为：

| 组件 | Commit | Tree | 仓库声明的 Rust |
| --- | --- | --- | --- |
| Chain S | `70df2c644ed8dd64afa1e7533743664cddacb9da` | `ef6eee36f4ac1cc823b29a2e499e2f2ef6b54855` | `1.95.0` |
| Runtime R2 | `70115620a7f540c8618a9b0d32ead20f8bc508f0` | `ebd1437475d71252786788f67d2911f5a6e6108d` | `1.96.0` |

`source-pair.json` 记录 37 份固定 Git 源文件的 blob、SHA-256 与长度，以及原先 5 份按原归属保留的 Chain 历史 receipt；另单列 dba 上的 peer 验证记录，均不移交给 S。新增 product fixture pin 为 `d87d97f193a6095e77a60fb3cb1894f77ebc6f95`，SHA-256 `5baaac0f3034422f28bdbd14379b2d8bb08a42eb84c8e174245aa171d3649b32`，33,165 bytes。workspace manifests/locks 和所有此前列出的 runtime source pins 与 R1 相同。

R2 在 parent `9e8faef449a4392b7b9aa6a9071f260a34d95ec9` 上保留并行证据，只对原 product fixture 的错误执行显式 anyhow 转换；provider/run/step、payload、checkpoint、四测试名和验收条件未改。旧 S/R1 的发布与执行记录保留原范围。

## 当前执行归属

- R1 `fc0c6f74...`：9 frontier unit 已真实通过；product target 编译 E0277，product 执行数为 0。两者原记录均保留，不移交给 R2。
- R1 的 154 个 CI 源/合成日志审计用例同样保留原 source；其 native 执行为 0。
- R2 已实际完成新的 154 项 source/合成日志审计，全部匹配预期、exit 0；前后 12 输入字节和 source clean 身份一致。该审计 native 执行为 0，`audit_did_not_trigger_ci = true` 只限定审计自身。R2 随后独立执行原生门：9 项 frontier 全部通过；4 项 product 实际运行 2 通过、2 失败、0 跳过。两项回滚拒绝通过；两项正常启动在真实 Agentd 子进程绑定 Unix 控制套接字时遇到 EPERM，product 门仍未通过。
- 旧 M06 的 246 passed / 8 既有 ignored / 25 targets 仍只归属 `14fcbede...`；其测试程序不充当部署 binary。230 个研究测试仍归属 `dbc24913...`，52 个输入相同的比较对象仍为 ef1。

- R2 inference-host 库测试在链接阶段以 SIGBUS 退出，执行数为 0，原因未确定；三包 `just fix` 两次均明确因 ENOSPC 失败，源码均未改变。这些门仍未通过。
- 早先的 Bazel 锁更新成功，但没有完整捕获命令边界的源码状态；其独立 scope receipt 明确不归到 R2。

## 发布与部署范围

随附 `source-publication.json` 保留 S/R1 历史发布；其中的 Chain S 身份可用于本组合。`runtime-R2-source-publication.json` 单独记录 R2 的 expected-ref、force=false 和完整 fixture blob 回读。二者都仅为源码发布记录。最终 runtime 证据提交为 [`7530e4bc7aa61a0c23a5933fef4a65d86a586cf8`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/7530e4bc7aa61a0c23a5933fef4a65d86a586cf8)，完整保留 98 份文件及其索引；`runtime-evidence-publication.json` 记录远端回读。该提交不改变生产源码、CI 或锁，不被当作新的原生测试源码。

实际部署配置及经验收的 Node／Agentd 二进制组合仍未提供。product 门确实构建并启动了普通 Agentd 的原生可执行文件；这份测试构建及其指纹不构成部署资格。仓库配置、Cargo.lock、测试程序或 signed source labels 均不能据此建立普通入口、恢复工具、验收使用同一部署组合。

## 发布分支与固定候选的区别

最终发布前，Chain 分支已并行推进到 `2e3e1cc2df14f809dcbfb560b94bca2b37a48a35`，其 tree 为 `a8785b53959dc3ae94fefb1eda91d4b3c2531018`；自 2ef 起的 86 个变化包含 6 个非证据路径。这些新增代码、workflow 和证据全部保留。`publication-carrier-scope.json` 记录完整范围。

**固定验收候选仍为 S/R2。新 PR 分支头只是承载本证据的后续版本，不能替代固定 SHA，也不能继承 S 的源检查或旧原生结果。** 本轮没有在该更晚 carrier 上运行 native 或完整仓库检查；P0-1 的同一部署组合条件继续未满足。

## 保留的边界

R2 恢复门仍要求当前 PQ root、独立保留的新鲜 checkpoint/floor；home/run/workspace/fleet 四域外路径不等于独立保管或故障域。签名中的 source commit/tree 没有校验运行 binary。实际 Fleet installer/updater 尚未接入 Chain release-role 的生产根授权。

恢复投影不覆盖 separate `provider_invocation_*` 或 `automation_1.sqlite3`，默认 Shadow 也不提供独占消费保证。Q0/S0 在真实效果使本地进入 S1、但外部 Q1 尚未发布时仍可能与恢复的 S0 匹配；避免权限复用仍依赖 provider 或独立单调 owner。该源码推理边界不能用启动签名测试替代。

本清单分别记录 9 项原生 frontier、4 项真实进程 product 和 154 项源码／合成日志用例。两项正向进程验收仍须在允许 Unix 控制套接字的环境通过；完整迁移、密码／QROM、量子 PoN、真实 PQ wire 容量及独立恢复部署退出条件均保持开放。后续证据提交保留同一固定源码身份，不把文档提交或旧执行记录当作新部署验收。
