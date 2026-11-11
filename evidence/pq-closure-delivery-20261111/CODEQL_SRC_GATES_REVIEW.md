# C1 CodeQL：101 处 `src` 命中的局部源码与 cfg 复核

本补充只复核初始机械盘点中的 **101 个主位置、11 个文件**。其中 **98 处位于 9 个明确的 `#[cfg(test)] mod tests` 作用域内**；另外 **3 处位于普通模块，分别是两个公钥 SPKI 缓冲区和一个会流向 reveal salt 的解析缓冲区**。在这三个具体初始化位置，未建立硬编码运行时私钥或 seed 的证据。所有原始 finding 与 GitHub Code Scanning API 证据缺口仍保持未关闭。

源码固定为 C1 `c09dbbe9921da12db8bf7240a8a95a0e9a789e50`，tree `f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6`；使用既有 run `42955582992` 的 head SARIF。初始盘点已记录 head 与 prospective-merge 的主位置重复关系；这里没有新跑 CodeQL，也没有把这次阅读算作 CI 通过。

## 98 处：实际 cfg 作用域

下面的区间来自精确 C1 Git 源码中的属性与模块边界，不是文件名分类。`cfg(test)` 是可观察的源码编译条件；本次没有核验最终构建参数、链接内容或部署二进制，不能据此宣称所有已部署产物排除了这些内容。

所有路径均以 `trillionnium/crates/` 为前缀。完整位置、源码行、Git blob、字节数和 SHA-256 见 [codeql-src-gates-review.json](codeql-src-gates-review.json)。

| 文件 | 位置数 | `#[cfg(test)]` 行；模块范围 | 局部用途 |
|---|---:|---|---|
| `trnm-crypto-primitives/src/pq_candidate.rs` | 1 | 268；269–480 | 模式分离测试使用 `[38; 32]` 构造固定 ML-DSA seed |
| `trnm-pon-node/src/ancestry_index.rs` | 4 | 675；676–988 | index-only fixture 的 salt；进入测试 Header nonce 与哈希 |
| `trnm-pon-node/src/ingress.rs` | 3 | 2876；2877–5440 | 明确 `#[test]` 的取消、重组与恢复场景调用局部 transfer helper |
| `trnm-pon-node/src/store/task_observation.rs` | 6 | 191；192–538 | 测试交易 common 字段中的 nonce |
| `trnm-protocol/src/funded_service_task_v1.rs` | 6 | 235；236–420 | reservation/task-id 绑定与改变上下文的 nonce |
| `trnm-transport/src/lib.rs` | 12 | 409；410–645 | 帧 admission、replay、recovery 与拒绝测试的 nonce |
| `trnm-types/src/relay.rs` | 43 | 545；546–1064 | sample_env 的显式 nonce 字符串与 sign_for_test |
| `trnm-types/src/transcript/mod.rs` | 19 | 84；85–202 | sample_env 的 nonce；签名字段是合成的 `sig-{seq}` |
| `trnm-worker-agent/src/workflow_ops.rs` | 4 | 89；90–160 | shell quoting、命令模板与输出结构测试的固定值 |
| **合计** | **98** | **9 个受显式 cfg 约束的模块** | **1 个测试 seed、4 个测试 salt、93 个测试 nonce** |

这里确认了测试生成器与测试输入的局部用途；没有验证它们是公开标准的 known-answer vectors，也没有审计每个 helper 的全部调用者或受测协议的安全性。测试中的固定 seed 是实在存在的，不应因属于测试而从原始 finding 计数里删除。

## 3 处：普通模块的局部数据流

### `pq_auth.rs:125`：复制调用方提供的公钥 SPKI

`from_pinned_spki` 先经 `ml_dsa_65_key_id_from_spki` 检查 SPKI 的 1,974 字节长度与 DER 前缀，再比较期望 key-id，并用公钥切片构造 `VerifyingKey`。第 125 行初始化的数组在下一行由 `copy_from_slice(spki)` 全量覆盖，之后才存入返回值。原 SARIF 的 key sink 是第 123 行的 `VerifyingKey::new_from_slice`，属于公钥解析。

这支持“在该函数成功返回的局部路径中，零字面量是复制目标缓冲区”的判断。它不验证期望 pin 的信任来源、公钥授权、全部调用者或整个验证协议。

### `pq_auth.rs:279`：编码由参数密钥派生的公钥

`public_spki(key)` 先分配同样大小的数组，随后向互不重叠且覆盖全数组的两段复制 22 字节 DER 前缀和 `key.verifying_key().encode()`。成功返回时两段已经写入。所读 `from_owned_seed` 路径的 `SigningKey` 来自调用方传入的 `Zeroizing<[u8; 32]>`；该零数组没有在这个局部路径中作为签名 seed 输入。

这只说明所选初始化与序列化的关系。调用方 seed 的随机性、保管、授权和其他创建路径仍未在本补充中建立保证。

### `public_evaluation.rs:52`：解析缓冲区确实会进入 reveal salt

`digest` 取得 JSON 字符串字段，检查它恰为 64 个 ASCII 小写十六进制字符，然后初始化 `[0; 32]`，调用 `hex::decode_to_slice`；解码错误通过 `?` 返回，之后才 `Ok(out)`。第 353 行通过 `digest(stored, "salt")` 构造 `Reveal.salt`，第 360 行重新核对 commitment，原 SARIF 指向第 270 行 `value.salt`。

因此该位置具有实际密码学上下文，不能归类为仅供展示或普通无关哈希。**缓冲区的零初始化并不证明 salt 随机性、输入认证、无 grinding 或整个调用链安全。** 本地格式校验允许 64 个零；本次未独立审阅第三方 `hex` 解码器实现，也没有证明上游 salt 生成与输入信任边界。记录上述写入与错误处理，不等于关闭该 salt finding。

## 可复核的证据与限定

读取固定 C1 Git object 时禁用 lazy fetch、replace objects、交互提示与可选锁；所读文件的实际字节、SHA-256 和 Git blob ID 均与冻结的完整源码快照比对。快照的 before/after 字节相同。仅在内存中读取已有压缩包中的必要 SARIF，没有展开大包；没有导入、编译或执行目标源码、测试、CI 或原生 workload。

- [初始机械盘点](CODEQL_FINDINGS_REVIEW.md) 与 [原始位置 JSON](codeql-findings-review.json)：两文件原字节保持不变。
- [本次逐文件与局部证据 JSON](codeql-src-gates-review.json)：101 个位置、9 个 cfg 区间、3 条局部流、原 SARIF sink 和所有已读源码 pin。
- [冻结 C1 hosted 包](../pq-closure-hosted-c09dbbe992/)：六格执行成功、原 SARIF finding 与 API gap 是各自独立事实。
- [冻结 C1 原生源码观察](../pq-closure-native-observations-20261111/original/)：用于绑定源码字节，不把源码身份比对解释为业务资格通过。

这次补充没有对另外 756 个主位置做语义审阅，没有作完整 interprocedural 或部署可达性证明，没有标记 false positive、关闭、忽略或抑制告警，也没有建立整链抗量子资格。下一步对所选三个普通模块位置的判断，需要审阅者结合第三方写入契约、实际调用方输入与密钥/盐来源；对 98 个测试位置的部署结论，则需要实际构建配置与产物证据。

## 精确 C1 源码索引

- [公钥校验与复制](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs#L118)。
- [公钥编码与完整覆盖](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs#L278)。
- [调用方 seed 参数](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs#L187)。
- [SPKI 长度与 DER 前缀检查](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-protocol/src/pq_frame.rs#L105)。
- [salt 解析与错误传播](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs#L43)。
- [reveal salt 重新绑定](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs#L337)。
- [固定测试 seed 与模式分离](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/c09dbbe9921da12db8bf7240a8a95a0e9a789e50/trillionnium/crates/trnm-crypto-primitives/src/pq_candidate.rs#L418)。
