# 跨仓证据检查点：ea909 × ed8928

**结论：HOLD。** 本检查点记录已经实际执行的固定组合、原失败分母及内部审查材料。没有合并、部署、激活或协议迁移。

| 组件 | 固定身份 |
| --- | --- |
| Chain | `ea909124cc460f364bd17b009073306014133f48` |
| Chain tree | `96712231eba3d333bdfebefa9c22c80ea1794d04` |
| Hepta | `ed8928db742825716791d45dca1158385c55737d` |
| Hepta tree | `fc251739c9a355202b047cb44d19b49ecf793106` |
| Chain 固定 merge | `cabef06fbe102cc32be2567137958374e242af45` |
| Hepta 固定 merge | `001fec5f869bd5a709ea7219f88116c7049a9b1a` |

实际 Cargo/Bazel 图的三条 Chain 依赖均固定到 ea909。源码与参考材料 descriptor 的文件 SHA256 为 `c0d71a2232da962ade261b82abb86b220dc5af560d6c21ea1eea930c2d30a0b6`，canonical binding SHA256 为 `339080f6f6f75f6b8d3f0f6e0099b98f485326493e7fbd286abb74eb135e37e3`。

## 实际观察

| 门 | 完整记录 |
| --- | --- |
| Chain 原私有 native | 89 项全部执行，87 通过，witness CLI 与 endpoint CLI 失败；严格 Clippy 通过。 |
| Chain 补充 native | Host、storage-owner、crypto、DA 与严格 changed-package Clippy 通过；独立记录，不替代原失败。 |
| SQLite | 原四项同缓存转换及两项附加 loader 控制均实际通过。 |
| 原公开 F0 | 原四秒 SLO 内 0/6；全部 42 个计划 packet exposure 保留。 |
| 原公开 native | 0/3 完整 campaign；27 轮 = 6 次原30秒内确认 + 9 次已观测失败 + 12 次未观测失败；受攻击确认 0/18。 |
| Hepta 原 native | 171 个 scope invocation 中 170 个通过；daemon 两次原60秒尝试均在完成26/31个恢复后超时，未进入 daemon start。 |
| W1 当前 CI | 20 个 component jobs success，两个 fresh-service jobs failure；未取得外部独立验收。 |
| CodeQL | exact-source 前置通过，analysis/check stabilization 超过原期限。 |

当前 Chain 原生证据归档已实际重读全部 **53 个声明二进制路径**并匹配，859 个实际 archive members（含 manifest）也逐一匹配。该收集成功不改变原 native 的 87/89 结果。Hepta 保留 12 个实际 ELF 身份；每 scope 的依赖 fence 与 post-native 全 tracked 字节对照边界均在包内写明。

历史9f归档范围已纠正：其46项 post-native readback都是live build output，另7个 retained copy 路径未在该次归档重读；原逐 invocation before/after 证据独立保留。

## 尚未满足的关闭条件

Hepta 当前 workflow 仍固定旧04be Chain profile，该 CI 结果记为 `NOT_CURRENT_PAIR`。V12 精确 source/manifest/workflow 修订已完成内部审读和完整 source controls（116→125）；本检查点不把未进入当前固定组合的修订算作运行结果。

普通 SmolLM 的11成员规格为272,189,990字节，当前仍是未执行的内容获取方案。参考材料16文件／91,512,155字节与普通入口分开记录，权限维持 `DENY_ALL`。当前授权、普通采用、重启、下一任务使用及独立未见任务净收益均未成立。

W1/量子完整成本与外部接受、全部实际PQ权限路径、独立托管与整机回滚，以及同一预算内离线发布者、独立域失败、修复、续期、GC和支付的长期闭环仍开放。NG／Prism／DAG未迁移。

## 文件

- [review-evidence.tar.gz](review-evidence.tar.gz)：67个精确选择文件及包内 inventory；921,612字节，SHA256 `3ab24b63da037a58897398a82c3a5f47fdf8a2b327a4ab627219080b921680ab`。
- [inventory.json](inventory.json)：逐文件尺寸、SHA256、范围和排除项。
- [bundle-receipt.json](bundle-receipt.json)：压缩字节和实际成员验证结果。

包内保留原目录结构。大型CI ZIP、ELF字节、模型权重和临时下载授权URL不在本检查点；原artifact ID与hash在相应审查内，未用摘要代造缺少的原执行。

源代码审阅入口：[Chain draft PR756](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/756) · [Hepta draft PR5222](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5222)。
