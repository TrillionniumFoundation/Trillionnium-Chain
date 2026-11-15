# M5 native library evidence — complete observation, one failing test

**结论：`FAILED_LIBRARY_TESTS`。** 固定 M5 在 canonical static OpenSSL 3.5.9 环境完成五个既有 library harness 的完整无过滤执行：**2449 passed / 1 failed / 41 ignored / 0 filtered**。Workspace library `cargo check` 与 `clippy -D warnings` 均通过。唯一失败为 node journal 冷重开时的非阻塞锁/IO EAGAIN；保留原件，未重跑覆盖。此结果不能标成 native tests 全通过。

本包按两个 provider cohort 分开保存结果。前一 cohort 的成功用例不移作后一 cohort 的成功证据，也不跨不同 package selection、重试或嵌套子进程累加。

## 固定源码和执行范围

- HEAD：`3ad605ecdac4b3b123dff83c1cb7458430acd776`。
- Tree：`fbbb4dca143775bae75ea825ff502f368e122ebb`。
- Parent M4：`e4e4a8e049915ba09d9e97444b4709ce8769ce81`。
- `Cargo.lock` SHA256：`f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd`。
- Rust/Cargo：1.95.0；`--offline --locked --all-features --lib`；Cargo/build `-j2`。`-j2` 是编译并行参数，不代表 libtest 仅运行两个线程。
- ROG 独占目录：`/home/qian-qi/chain-hepta-481716-native-check`。未改系统 OpenSSL，未改源码。各执行前后源码、lock、实际 ELF、provider inputs 都有身份记录；收集时仍为上述 clean M5。
- 实际二进制均为 `cfg(test)` / test profile library ELF。ordinary daemon build/load 身份字段为空。

M5 的 Rust 变更仅在 sealed-loader 测试判据：用原 FD 的 dev/ino 区分已关闭原对象与后来复用的整数槽，增加 live-original 反向控制。生产 sealed-loader 未改变。DA 715 条完整测试中原 corruption 测试和新增反向控制均实际通过。

## 两个独立 cohort 的完整结果

表内数字依次为 passed / failed / ignored；各行顶层 filtered 均为 0。

| Library | System dynamic OpenSSL 3.5.5 | Canonical static OpenSSL 3.5.9 | Canonical libtest elapsed |
|---|---:|---:|---:|
| `trnm-data-availability` | 715 / 0 / 0 | 715 / 0 / 0 | 20.64s |
| `trnm-crypto-primitives` | 196 / 0 / 0 | 196 / 0 / 0 | 0.36s |
| `trnm-pon-node` | 1359 / 0 / 39 | 1358 / 1 / 39 | 361.64s |
| `trnm-protocol` | 113 / 0 / 2 | 113 / 0 / 2 | 6.27s |
| `trnm-release-bundle` | 56 / 11 / 0 | 67 / 0 / 0 | 8.68s |

### System dynamic 3.5.5 历史 cohort

只读 probe 通过实际 libcrypto 的 `OpenSSL_version(0)` 观察到 3.5.5，并记录了 ELF 动态依赖、库路径/字节 SHA、Cargo fingerprint 与 build-script 输出。该版本满足代码 `>=3.5` 的版本 floor。11 个 release Root fixture 最先失败于缺少 `TRNM_PQ_OPENSSL` 环境变量；因此不能把它们归因于算法或版本不支持，也不能把前置失败当成后续安全断言已执行。

前一次五包 `--no-run` 构建的五个 ELF 随后逐个实际执行。上述 node 1359/39 属于这一旧 cohort；不能转移到 canonical cohort。所有旧 ELF 原实体在 ROG 专属 `m5-previous-system355-test-elfs/` 保留并验证了 SHA，未塞入小日志包。

### Canonical static 3.5.9 cohort

严格使用仓库原 `scripts/ci/prepare_pq_provider.sh`，脚本 SHA256 `ccdcf7e8bb9871607c73adc78624a607b616c227b7fe581b96c48761a3805bfa`。下载的 3.5.9 archive 按固定 SHA256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a` 核验，原 static build 与 ML-DSA-65 key/sign/verify/wrong-message smoke 成功。原脚本执行约 64.84 秒，完整 build-and-smoke 日志保留。

7 个导出字段在编译前和实际 test 运行时绑定：`OPENSSL_DIR`、`OPENSSL_STATIC=1`、`TRNM_PQ_OPENSSL`、`TRNM_PQ_OPENSSL_SHA256`、`TRNM_PQ_OPENSSL_VERSION=3.5.9`、`OPENSSL_CONF=/dev/null`、`OPENSSL_MODULES`。各字段完整值在 provider receipt、commands 和 execution-context 原件中。

- CLI SHA256：`742a393279b769f7b2bbcaabdcdd152d5565d5108b4b920c69c55a1d42c4e6d7`。
- `libcrypto.a` SHA256：`c82db203024d8d53f97a2f81161385f04444365232f5e2e6deaef77a2aff0468`。
- `libssl.a` SHA256：`d7cddef12614789118f792fb4b07748c9a413d241895c1501fe12e3998658d90`。

五包统一 selection 重构后，crypto、DA、node、release 四个 ELF 字节改变；protocol 字节未变。五个均在 canonical 环境重新实际执行。每个 ELF 的 `readelf -d` 原件都未出现动态 `libcrypto`/`libssl` 依赖；原 native backend input、build-script 输出和 fingerprint 同时保留。准备阶段的 ML-DSA-65 smoke 不替代 release 的 ML-DSA-87 / SLH-DSA Rust fixture；后一组在新 release ELF 的 67 条完整测试中实际执行并通过。

Canonical node 唯一失败：

```text
public_submit::pq::journal::tests::journal_unknown_publication_is_sticky_and_cold_replay_does_not_refund_attempt
crates/trnm-pon-node/src/public_submit/pq/journal_tests.rs:230:63
called Result::unwrap() on Err: Transport / IO: Resource temporarily unavailable (os error 11) / WouldBlock
```

失败发生在 `drop(journal)` 后 `Journal::open` 冷重开，相关 acquire 路径使用 `FileExt::try_lock_exclusive`。现有记录没有识别实际持锁者；不把相关性写成 provider 引发错误的因果证明。该 job `1a1c138d439-e62c-37` 的内层退出为 101，外层 wrapper 退出为 2，均未 timeout。两项 continuity 长测试均已 `ok`。源码、ELF 和 provider inputs 前后一致。失败原日志见 archive 中 `m5/canonical359/direct-trnm-pon-node-01/test.stdout.log`。

## 统一 feature 构建与实际执行身份

最初 DA 单包和随后四包的 Cargo 选择产生了不同 feature/dependency fingerprint；DA 单包 artifact 后缀为 `41bde8e9d9cfe9e6`。该探索结果独立保留。之后采用原五包选择 `--no-run --message-format=json`，从实际 compiler-artifact 事件取得五个 executable，未通过 glob 猜测。

Canonical 构建实际 argv（cwd 为专属 source 根）：

```text
/home/qian-qi/.cargo/bin/cargo +1.95.0 test --offline --locked --all-features --lib -j2 -p trnm-crypto-primitives -p trnm-release-bundle -p trnm-protocol -p trnm-pon-node -p trnm-data-availability --manifest-path trillionnium/Cargo.toml --no-run --message-format=json
```

此构建本身不运行测试。随后每个实际 ELF 都无 filter、无 `--ignored` 参数运行。cwd 使用对应 package metadata 的 `manifest_path` 父目录，例如 DA 为 `source/trillionnium/crates/trnm-data-availability`。执行环境由已观测 Cargo common environment、该包实际 metadata、owned build-script linked paths 和 7 个 canonical exports 组成；所有选定字段保存。未记录的继承环境仍然存在，**不声称与某次 Cargo test 的整个环境逐字相同**。

每条 direct command 独享 850 秒内层测试窗口，外层 Hepta 为 900 秒；编译窗口单独记录。该工程编排不提高原 Host 4 秒或 campaign 30 秒约束。后缀相同不代表 ELF 相同；以如下字节 SHA 和运行前后记录为准。

| Library | 实际 test ELF basename | Bytes | SHA256 |
|---|---|---:|---|
| `trnm-data-availability` | `trnm_data_availability-68d57059a66fd7c3` | 136048936 | `e99f7030260577c8063e27006baf361eacb6d24f3e7a3f9b2b14ad48865d00a1` |
| `trnm-crypto-primitives` | `trnm_crypto_primitives-a8181f6305c7ebfe` | 67326704 | `011e6ed77e28710b873ee0a0309aee7cdfa7c1af008941ff69c41581804709c5` |
| `trnm-pon-node` | `trnm_pon_node-1b9e88419cc32a23` | 576778400 | `00d50474c4409a5b89d14e5a75abbc7ca83cd41f6bdf0ae8a9605e49cb10deaf` |
| `trnm-protocol` | `trnm_protocol-d8b25a80c1197ac9` | 24337264 | `bb1f1f5530c29fce07616debe545460c58bbd4df021843a39eb287297ff8e413` |
| `trnm-release-bundle` | `trnm_release_bundle-a057cb68931339ff` | 46747168 | `c83235f198923321f530f662ffbf4251f87eac22ea24ef2e466daa0ee9946395` |

Canonical cached workspace library 检查实际 argv：

```text
/home/qian-qi/.cargo/bin/cargo +1.95.0 check --offline --locked --workspace --all-features --lib --manifest-path trillionnium/Cargo.toml -j2
/home/qian-qi/.cargo/bin/cargo +1.95.0 clippy --offline --locked --workspace --all-features --lib --manifest-path trillionnium/Cargo.toml -j2 -- -D warnings
```

两条返回 0；记录约 5.00 / 9.00 秒，为复用目标缓存后的工程观测，不是服务性能验收。固定 M5 `cargo fmt --all --check` 在 source-03 阶段已通过。

## 历史失败与分母保留

- source-01 被本地 runner 过严的“一路径变更”检查拒绝；M5 实际包含测试、文档、corpus 3 路径。source-02 因 detached HEAD 被原 preflight 拒绝。source-03 回到原专属开发分支后通过。前两次未运行测试，原 receipts 保留。
- 初始四包 Cargo 尝试因增量编译约 7m09 占用工程窗口，在 850 秒终止；仅 crypto 顶层 196 完整通过，node 顶层未完成，protocol/release 未开始。原件保留 inner timeout 与外层非-timeout的区别。
- 初始四包 summary 的 `ignored_tests_remain_unexecuted=false` 仅依据已完成 crypto 计算，遗漏了未完成 node 中已观测的 39 条 ignore。`m5/reader-corrections/four-ignored-01.json` 以原 summary SHA 另记更正；原 summary 不改写。
- Node 的 3 个嵌套子进程各 `1 passed / 1397 filtered` 单独保留，不算成 3 个 crate，不加进顶层总数。两个 cohort、初始不同 selection、重试结果不累加。
- 旧 system cohort release 56/11 和 canonical cohort node 1358/1/39 均完整保留。canonical collector v1 草稿未执行；v2 分离“完整观测”和“全部通过”，因失败而给 `FAILED_LIBRARY_TESTS`，并保存 2449/1/41 实际总数。
- 更早 M4 的错误包名 NOT_STARTED、850 秒 timeout、嵌套误计 correction、FD 判据失败属于独立 M4 历史包，未覆盖。

## 仍开放的验收边界

`retained-ignored-tests.json` 给出 node 39 + protocol 2 的逐条原 ignore 文本。包括原 `store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen` explicit release gate。没有启用 ignore 或删筛断言。

本轮普通 daemon 学习闭环、原 4 秒 Host、独立 30 秒 campaign、History/capacity/churn 分别服务验收、真实冷下载/长期保管、独立运营/WAN/故障域/长期租约均未由这些 library tests 关闭。新 node 测试失败仍是 native validation 阻塞。没有执行压力 campaign、外部攻击工作流、72h gate、examples 或全 workspace test。Provider preparation 和 Root fixture 通过也不构成整链量子安全或生产激活证明。

## 交付与完整性

- `validation-logs-01.tar.gz`：ROG 原始日志/源码身份/实际 ELF identity/feature、provider、commands、测试名单、所有阶段 summary 和独立 correction，共 471 个原始文件，加一个 manifest。gzip mtime=0。
- `controller-records-01.tar.gz`：原始请求、准备失败、runner、24 个 durable job 的 start/status 和完整 stdout/stderr；未提交的草稿请求与实际 job 通过 terminal index 区分。
- `controller-terminal.json`：24 jobs / 48 streams，逐流实际字节均等于 terminal stored 和 seen。外层 controller `timed_out=false` 不覆盖内层 timeout。
- `archive-summary.json` 为远端原字节；`remote-transfer-receipt.json` 保存 pinned file version、全部 chunk SHA 与 whole SHA；`local-validation.json` 保存安全 member 与 471 文件 size/SHA 校验结果。
- 日志包不包含 build targets、旧/新 ELF 实体、provider buildroot 或新鲜 smoke key。需要的二进制身份均保留。
- `FILES.json` 和 `SHA256SUMS` 列出本目录交付文件；hash manifest 自排除，避免循环。

详细事实以本目录 immutable archive 原件为准。可进一步定位 node EAGAIN 的真实持锁者或修复明确根因，但本包没有执行“无变更重试直到绿”。
