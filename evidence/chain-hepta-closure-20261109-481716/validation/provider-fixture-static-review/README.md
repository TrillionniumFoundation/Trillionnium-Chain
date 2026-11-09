# M5 release fixture 的 OpenSSL 身份审阅

**仅补 CLI 环境变量只能修复第一个 fixture 前置条件，不能证明现有 Rust ELF 已使用 canonical OpenSSL 3.5.9 静态 backend。** 本次只读固定 M5 `3ad605ecdac4b3b123dff83c1cb7458430acd776` 的源码、依赖和 CI 约束，没有运行测试、生成密钥、更换 provider 或修改源码。完整源码 SHA 与判断边界见 [review.json](review.json)。

## 已报告的失败与实际环境

Root/native-run owner 报告原 `trnm-release-bundle` 共 67 项：56 pass、11 fail，首故障位于 `root_recovery_v3_tests.rs:17` 的 `TRNM_PQ_OPENSSL` 读取；紧接着还必须提供 `TRNM_PQ_OPENSSL_SHA256`。11 个失败保留为失败，不能改为“已通过的业务断言”。本 reviewer 尚未独立读取完整原失败日志，其计数按运行 owner 的报告登记。

Native agent 随后的只读 probe 报告，原 ELF 动态链接 **OpenSSL 3.5.5**，七个 provider 环境变量均为空，已有归属目录内未找到 3.5.9 preparation receipt。所报 libcrypto SHA 为 `5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28`，libssl SHA 为 `63b47f444efa588e291e9b650a5ba2ab02f856356f2d50f13a2e477db9119e09`。这些是 native agent 的测量报告；本 reviewer 尚未本地重核原 probe 输出或旧 ELF 完整 SHA，JSON 已明确区分这一来源。

**3.5.5 满足源码的最低 `>=3.5.0` 检查。** 因此当前失败只证明先发生的 fixture 环境缺项，不能据此断言算法不受支持。补输入后的算法实际运行尚未由本次审阅证明。即使 3.5.9 CLI 可在该旧 ELF 配合下工作，这也是 CLI 3.5.9 / Rust 动态库 3.5.5 的混合身份，不能登记为 canonical 3.5.9 静态构建。

## 两条依赖路径

| 步骤 | 实际使用者 | 源码含义 |
| --- | --- | --- |
| 读取 CLI 路径和 SHA | fixture | 实际 CLI 字节与环境中的 pin 比较；这个自洽比较本身不证明 pin 来自 canonical preparation |
| 生成两族 DER 私钥 | CLI 子进程 | `ML-DSA-87` 与 `SLH-DSA-SHA2-256s`；子进程单独强制 `OPENSSL_CONF=/dev/null` |
| 解析私钥、导出公钥 | Rust 链接的 OpenSSL | `PKey::private_key_from_der`、`public_key_to_der`；不是 CLI 的执行结果替代本地解析 |
| 两族 fixture 签名 | Rust 链接的 OpenSSL | `Signer::new_without_digest`、`sign_oneshot_to_vec` |
| 原 quorum/possession 验证 | 真实 verifier | 先检查 Rust backend 版本；ML-DSA-87 走 RustCrypto CandidateVerifier，SLH-DSA 走 Rust EVP PKey/Verifier |

依据：[完整 fixture](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-release-bundle/src/root_recovery_v3_tests.rs#L15)、[quorum/possession 版本检查入口](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs#L269)、[实际版本与两族验证分流](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs#L513)。

`Cargo.lock` 固定 Rust 包装层 `openssl 0.10.81`、`openssl-sys 0.9.117`，没有 `openssl-src` 条目；它没有固定系统 `libcrypto` 的实际字节。`pq-root-v3` 启用可选 native OpenSSL 依赖，但不会在运行旧 ELF 时重新链接另一个 prefix。依据：[release feature/dependency](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-release-bundle/Cargo.toml#L12)、[Cargo 原锁](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/Cargo.lock#L670)。

## canonical preparation 实际证明什么

[原 prepare_pq_provider.sh](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/scripts/ci/prepare_pq_provider.sh#L23) 固定 **OpenSSL 3.5.9** 与 source archive SHA-256：

`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`

它在独立 prefix 使用 `no-shared no-tests` 构建并保存两份静态库；通过实际 **ML-DSA-65 CLI** 的 keygen、sign、verify、wrong-message rejection 后，才导出 `OPENSSL_DIR`、`OPENSSL_STATIC=1`、CLI 路径/SHA/版本、`OPENSSL_CONF=/dev/null`、`OPENSSL_MODULES`。receipt 保留 CLI、两份头文件、libcrypto.a、libssl.a 的实际身份。

这个 smoke **没有执行 Rust native 测试，也没有证明本 fixture 的 ML-DSA-87 + SLH-DSA-SHA2-256s 场景通过**；脚本也未运行 upstream full tests。已有 [CI wiring control](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/scripts/ci/test_pq_provider_ci.py#L50) 要求 provider 准备在 PQ compilation 之前。后补环境标签不会改变原构建身份。

## 必要的实际身份闭包

1. **准备原件**：固定 archive SHA、M5 脚本 SHA、成功且未覆盖失败的 provider receipt/log、真实 CLI version/SHA、头文件和两份静态库 SHA，以及 smoke 的实际结果。
2. **编译身份**：M5/tree、Cargo.lock、工具链、package/features/profile，编译时的 `OPENSSL_DIR/STATIC` 和实际适用的 target override；保留 openssl-sys build-script output、Cargo fingerprint、链接输入与新 compiler-artifact ELF SHA。仅看到 ELF 无动态 `NEEDED libcrypto`，还不能证明静态内容来自选定 archive。
3. **运行身份**：实际测试 ELF 前后哈希、argv、package cwd、Rust 进程实际 provider 环境。动态构建还需解析出的库路径、库字节 SHA 和该库自身版本；`libcrypto.so.3` 这个 SONAME 不足以确定 3.5.9。CLI 的子进程 CONF override 不等于父 Rust 进程的 CONF/MODULES 设置。
4. **结果身份**：保留原 56/11 attempt；新 build/runtime 身份另开实际测试记录，保持原 roster、断言和 failed/ignored/filtered 口径。准备或编译成功不能替代原测试通过，也不能关闭生产或 PQ 资格。

Native agent 已获准使用原脚本准备隔离 provider。合适的后续范围是完成该准备并在它导出的静态 backend 下编译，再按新二进制身份执行原测试；这里不建议用未验证的现成 provider、删除断言或改动源码来消除环境失败。
