# 当前密码配置源码比对（有界静态审查）

- 基准：`885b6e82a1470f6a35b55fa8d3c95af44d2afea8`，tree `f81eafd69e890d81b919ddb92a66fed149ad7aef`。
- 当前：`59f75acd1d4261972b8aaa45e0c36259fcafd45c`，tree `c0dc8282e5b2618ffb35061f108bb2fa96e9b348`。
- 逐路径 Git blob、完整树差异清单和实际阅读过的函数见 [current-source-comparison.json](current-source-comparison.json)。树差异清单只代表身份变化，不代表逐项语义审计。

## 保留情况与实际变化

32 个指定路径中 **28 个 blob 相同、4 个变化**；原 23 个交付路径中 19 个相同，包括全部 15 个 Rust 实现／测试／基准文件、安全说明、证据 README 和两份独立读取脚本。4 个变化是 corpus pins、开发计划、集成检查器和生成的 distributed source inventory。

ML-DSA-65 基线、CPQ1 的 65／87 候选、可信状态选择及历史／当前类型分离均保留。`select_current` 仍拒绝候选；收到的 ID 只用于比对。候选限制为消息 65,536 B、整帧 131,072 B、最多 8 签名者、累计 64 次验签及 8,388,608 B，预算失败会锁定且不退款。状态真实性和最终业务授权仍由调用方承担。

原 **49 个 required controls 名单完全相同**；这不是 49 项已执行的结论。pins 从 410 增到 462，required paths 从 322 增到 379，旧项无删除，8 项升级／授权声明仍全部为 false。

workspace、protocol、crypto manifests 与 SHA-2 Linux x86_64／aarch64 `asm` 配置不变。主／fuzz lockfile 分别仍有 180／147 个 package table，包版本／来源／checksum 元组无变化；实际变化是 M15 增加 crypto／protocol／zeroize 依赖边，M09 的 serde／serde_json 转为普通依赖。**这两个数字不是 Cargo metadata 解析结果。**

## 已读源码的哈希用途边界

| 用途 | 实际算法与输出 | 边界 |
|---|---|---|
| registry `crypto_profile_id` | SHA-512，64 B | 完整配置及绑定的身份；不自动认证状态 |
| CPQ1 key identity | SHA-512，64 B | 已有候选编码／验签辅助使用；候选无当前授权 |
| 候选 payload／state／release／proof／address／Merkle／transcript | 带 profile、用途和长度的 SHA-512，64 B | 通用规则／helper 已实现，不能推断各生产子系统已迁移 |
| legacy key identity | 域前缀＋严格 DER SPKI 的 SHA-256，32 B | 保留原协议；编码检查不是公钥密码学验证 |
| legacy payload | 域／用途／长度绑定的 SHA-384，48 B | 保留 TPQ1 |
| PNQ policy digest | 原 `pon_wire::hash` SHA-256，32 B | 与新增 64 B profile ID 分开 |
| M15 root signing digest | SHA-512，64 B | 纯 ML-DSA-65 的项目消息构造，不是 HashML-DSA |
| M15 root identity／checkpoint | SHA-256，32 B | **未接入 `crypto_profile_id`** |
| M15 metadata content | 外部提供的非零 32 B 值 | 一般 role 的算法未由该字段确定 |
| M15 NodeSoftware bundle content | V0 SHA-256，32 B | `accept_bundle` 显式绑定 bundle digest；不外推其他 role |
| native W1 challenge／ticket | 原 SHA-256，32 B | work／wire／配置 blob 均未变 |
| 外部 work 配置引用 | SHA-512，64 B | 只是精确配置字节的引用，不改变 challenge／ticket／关系 |

正式 W1 relation 源码变化仅在 `#[cfg(test)]` 内加入三项测试，生产前缀相同；不能据此宣称可选 hardened verifier 全部未变或已获工作安全资格。

## 结论与证据边界

本次有界静态比对未建立新的具体授权、编码或预算缺陷；核心实现 blob 相同不等于无缺陷证明。M15 的独立 ML-DSA-65 suite、SHA-256 root／checkpoint 与通用 SHA-512 候选规则之间仍有明确集成边界。

已发布 ad081 历史证据保持原字节。丢失的 885 临时日志没有重建，也没有移作 59f 的通过结果。本文件不包含新的 Cargo／native／门禁执行结果；当前实际运行须以独立 `current-validation` 命令记录为准。整链 PQ、87 激活、CURRENT／FinalUse、物理回滚恢复、WAN 和 W1 工作安全均未因此获准。
