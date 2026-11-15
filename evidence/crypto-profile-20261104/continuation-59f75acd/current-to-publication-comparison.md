# 固定59f到并发发布基线ac240：有界增量审查

本轮实际运行固定于 `59f75acd1d4261972b8aaa45e0c36259fcafd45c` / tree `c0dc8282e5b2618ffb35061f108bb2fa96e9b348`。
远端观察到的直接后继是 `ac2402e4c8b99eee21c6db3e28f8984071478797` / tree `68c5fda28e64f689cabbee8cd8ae99cc7050dd74`。
实际最终发布提交尚未确定。18路径的GitHub原始差异及逐路径blob见
[current-to-publication-comparison.json](current-to-publication-comparison.json) 和 [ac240-compare-metadata.json](ac240-compare-metadata.json)。

## 保留与真实语义变化

- profile／CPQ1、65基线、65／87候选拒绝激活、历史／当前类型分离和累计预算保持原源码；原49名单、Cargo manifests／lockfiles、native W1也未改。
- checkpoint owner现在拒绝StructuralOnly对象的直接运行时读／CAS，校验实际完整journal前缀和sibling head；读head最多85 B，前缀检查成本O(record count)，不能声称常量成本或物理全副本回滚防护。
- M15 CellActivation现在必须对应当前root且仍未过期的CellManifest发布授权；恢复重放保留这些事实。这修补了59f已有的授权条件缺口，不能通过升级签名参数替代。
- M15仍未接`crypto_profile_id`；root identity／checkpoint仍SHA-256／32 B，root签名消息的内部digest仍SHA-512。一般content仍是外部32 B值，NodeSoftware另有既有V0 bundle绑定。
- 新oracle调用真实TAP21函数，新SDKrunner使用固定securesystemslib的实际signer／verifier，保留旧C及source-attack路径；不是完整TUF updater、87激活或托管CI完成证明。
- pins 462→466，required paths379→383，无删除；所有八项声明仍false。

## 必须在独立发布工作树处理的整合项

新增 `trillionnium/crates/trnm-checkpoint-store/src/live_journal_v2.rs` 匹配inventory生成范围，但完整18路径差异未更新生成表，继承表也不包含该路径。
因此必须在独立publication工作树生成inventory、审阅新增项并精确更新其pin，再运行真实门禁。
这是源码推导出的整合问题，**未执行／伪造一个失败测试**；冻结59f不改。

## 并发观测的独立边界

并发compact manifest自述为工作树组件观察，source hashes在运行后采集，且未包含raw日志归档。
其中checkpoint all-target结果仍为43 passed／4 failed、exit101：一个unit直接记录Unix socket EPERM，另外三个process记录daemon启动退出；不能把它们全称为同一已知根因，更不能算通过。
原始red cases、SDK初次失败和被中断的build均保留；并发报告的18个release测试和SDK／C数量也不计入我们59f的通过数量。

此审查不启动任何runner、collector、Cargo或测试，不修改冻结仓库。所有新文档必须继续标明FIXED tested59f，而非远端最新或最终发布树的原生验收。
