# M6 native library validation — retained top-level ignored gates remain open

**本轮 native library 验证通过：2450 passed / 0 failed / 41 top-level ignored / 0 filtered。** 五库完整主 roster 共 2491 个定义，全部实际运行到顶层终态；Rust 1.95 的 workspace library check、严格 Clippy 和 fmt 通过。状态为 `PASS_WITH_RETAINED_IGNORED_GATES_OPEN`。

41 是顶层 libtest 的 ignored 计数，**不能解读为 41 项在任何子进程中均未执行，也不能统称 41 个业务 gate**。原有父测试会显式调用一个 bounded ignored helper；这些 child 执行单独记录，不加主分母。原服务、容量、重型/发布 gate 仍未据此关闭。

## 固定源码与实际范围

- HEAD：`4dbeae12fa756fd662cc074390fcb628abe970ad`。
- Tree：`1943c3e69e3a717ce99d91aabc00eba4d37516f1`。
- Parent M5：`3ad605ecdac4b3b123dff83c1cb7458430acd776`。
- `Cargo.lock` SHA256：`f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd`。
- 原允许开发分支 fast-forward，exact source/preflight/fmt 均通过；执行前后及最后收集时源码 clean、HEAD/tree/lock 一致。
- 与 M5 恰有 3 路径变化：journal 测试、sole development plan、corpus 的两处 blob pin。生产 `files.rs` / `journal.rs`、Cargo.lock 与 provider preparation 脚本不变。
- ROG 专属目录 `/home/qian-qi/chain-hepta-481716-native-check`；复用 own targets，Rust/Cargo 1.95.0、offline/locked、all features、libraries、Cargo `-j2`。未并发启动多个 Cargo/native validation job。

## 五库实际结果

| Library | Main roster | Passed | Failed | Top-level ignored | Top-level filtered | Libtest elapsed |
|---|---:|---:|---:|---:|---:|---:|
| `trnm-crypto-primitives` | 196 | 196 | 0 | 0 | 0 | 0.35s |
| `trnm-data-availability` | 715 | 715 | 0 | 0 | 0 | 20.15s |
| `trnm-pon-node` | 1398 | 1359 | 0 | 39 | 0 | 361.75s |
| `trnm-protocol` | 115 | 113 | 0 | 2 | 0 | 6.29s |
| `trnm-release-bundle` | 67 | 67 | 0 | 0 | 0 | 8.74s |

所有测试二进制均来自原五包 selection 的一次实际 `--no-run --message-format=json` 构建。该编译阶段约 132.76 秒；未把构建当作测试通过。随后五个 compiler-artifact executable 均完整实际运行。四个 ELF 与 M5 canonical 字节相同，node ELF 改变；没有把旧 M5 的 PASS 代替任何本次运行。

## Journal 场景的测试隔离与原始 child 输出

M6 仅把原 `journal_unknown_publication_is_sticky_and_cold_replay_does_not_refund_attempt` 整个测试场景放到 exec 后的同一 child 内执行：initialize、活跃 owner、原 fault、drop、cold reopen 和全部原 assertions 保持在同一 child，原 60 秒 plan 不变。新增第二个 live owner 必须返回精确 `WouldBlock` 的控制。没有把 producer 与 reopen 分到 exec 两侧，也未修改生产非阻塞锁。

父测试实际检查 child exit success、`running 1 test` 和完整 body marker，并传播错误。M6 外层 node argv 唯一呈现变化是 `--show-output`，使成功测试捕获的 child stdout/stderr 可被保存；主 roster 仍为 1398，无主测试过滤、没有在外层启用 `--ignored`。其余四个 ELF argv 均只有 executable。

实际 journal child 原文另存 `journal-exact-child.log`；关键完整片段如下：

```text
---- public_submit::pq::journal::tests::journal_unknown_publication_is_sticky_and_cold_replay_does_not_refund_attempt stdout ----

running 1 test
test public_submit::pq::journal::tests::journal_unknown_publication_is_sticky_and_cold_replay_does_not_refund_attempt ... TRNM_PQ_JOURNAL_UNKNOWN_PUBLICATION_BODY_COMPLETE
ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1397 filtered out; finished in 0.07s
```

Node 原 job `1a1c1566852-e62c-70`：17:23:48.799 至 17:29:51.293 UTC，顶层 1359/0/39，361.75 秒。两项原 continuity 长测试均实际 `ok`。该新 journal child 是非ignored测试的精确子执行，其 1 passed /1397 filtered 单独记录，不加到顶层 1359。

M5 canonical 的 node 原失败 1358/1/39 和五库 2449/1/41 继续保留。原 EAGAIN 没有 PID/inode/时序证据识别真实持锁者，原因仍为 `unestablished`。**M6 通过不能倒推证明 M5 失败的原因。**

## 顶层 ignored 与既有 helper 的作用域更正

`retained-ignored-tests.json` 保存 node 39 + protocol 2 的原顶层 ignore 文本，以及 M5/M6 实际 child 观察。两版原 stdout 都明确出现：

- `operator_task_policy::file_tests::held_file_substitution_child` 顶层 ignored，随后由父测试既有 `--ignored --nocapture held_file_substitution_child` 调用实际 `ok`，1 passed /1397 filtered。
- 非ignored的 `store::authenticated_migration::tests::growth_rehearsal_file_reads_refuse_fifo_replacement_before_open` 有两次同名 child 执行，均独立记录。
- M6 另新增上文非ignored journal child，1 passed /1397 filtered；与 ignored helper 分开。

因此不把 3 条旧/4 条新 nested 摘要算作额外 crate，也不加入总数。原 `store::growth::tests::native_growth_v2_signed_cross_65536_bounded_io_zero_nonce_and_reopen` explicit release gate 等原服务/容量/重型 gate 仍未通过本轮执行关闭。

`ignored-scope-correction.json` 绑定未修改的 M5 README、ignored JSON 和原 archive SHA，纠正先前交接中“41项全部未执行”或泛称“没有启用ignore”的范围。Raw runner/collector 中 `ignored_tests_explicitly_enabled=false` 只描述外层验证 argv，不否认库内部父测试原有的 `--ignored` child 调用。M5/M6 原 archive 都不改写，也没有为这项说明重跑测试。

## 同一 provider 与二进制身份

复用 M5 已验证的 canonical OpenSSL 3.5.9 static prefix；M6 未重建 provider、未修改系统安装。每阶段核对原 7 exports、CLI/headers/static libraries 的字节 SHA，以及 M6 中 preparation script 与原 SHA 一致。原 provider source archive SHA：`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`。

- CLI SHA：`742a393279b769f7b2bbcaabdcdd152d5565d5108b4b920c69c55a1d42c4e6d7`。
- libcrypto.a SHA：`c82db203024d8d53f97a2f81161385f04444365232f5e2e6deaef77a2aff0468`。
- libssl.a SHA：`d7cddef12614789118f792fb4b07748c9a413d241895c1501fe12e3998658d90`。

`OPENSSL_DIR`、`OPENSSL_STATIC=1`、`TRNM_PQ_OPENSSL`、CLI SHA、version=3.5.9、`OPENSSL_CONF=/dev/null`、`OPENSSL_MODULES` 在编译和运行中相同。原 smoke receipt/full log 随包保留；smoke 不替代 ML-DSA-87 /SLH-DSA Rust fixture。本次 release 67 条在实际 canonical ELF 中重新通过。

Collector 强制实际 compiler-artifact 与每次 direct before/after 的 path/bytes/SHA/cfg(test) 相同，再核 source、provider、test profile、精确主 argv、package cwd 和 cohort。该 join 实际通过 5/5，并在本地从回收原件再次核验；不以单个构建成功布尔值代替身份关联。

| Library | Test ELF bytes | SHA256 | Compiler → before → after |
|---|---:|---|---|
| `trnm-crypto-primitives` | 67326704 | `011e6ed77e28710b873ee0a0309aee7cdfa7c1af008941ff69c41581804709c5` | 相同 |
| `trnm-data-availability` | 136048936 | `e99f7030260577c8063e27006baf361eacb6d24f3e7a3f9b2b14ad48865d00a1` | 相同 |
| `trnm-pon-node` | 576819920 | `905779facac297c3ce3387d4142ea11dd20db397a73969043dc72cb520909ee3` | 相同 |
| `trnm-protocol` | 24337264 | `bb1f1f5530c29fce07616debe545460c58bbd4df021843a39eb287297ff8e413` | 相同 |
| `trnm-release-bundle` | 46747168 | `c83235f198923321f530f662ffbf4251f87eac22ea24ef2e466daa0ee9946395` | 相同 |

所有均为 `cfg(test)` / test profile，ordinary daemon build/load 身份字段为空。M5 canonical 五个旧 ELF 原实体在 ROG own directory 另行复制、逐 SHA 验证后才构建 M6；实体未塞入日志包。

## 命令、cwd、环境与时间边界

原五包统一构建 argv：

```text
/home/qian-qi/.cargo/bin/cargo +1.95.0 test --offline --locked --all-features --lib -j2 -p trnm-crypto-primitives -p trnm-release-bundle -p trnm-protocol -p trnm-pon-node -p trnm-data-availability --manifest-path trillionnium/Cargo.toml --no-run --message-format=json
```

Direct test cwd 均为各实际 package metadata `manifest_path` 父目录；环境由已观察 Cargo common environment、当前 package metadata、owned build-script linked paths及7个固定provider exports组成，选定字段完整记录。没有声称未记录的继承环境与某次 Cargo test 的整个环境逐字相同。

每个 direct test 有独立 850 秒内层工程窗口、900 秒外层 job；编译窗口单独记录。node 的 `--show-output` 是唯一额外呈现参数，其余四库 bare argv。该编排不改变原 Host 4 秒、campaign 30 秒或产品请求预算。

M6 workspace library 检查：

```text
/home/qian-qi/.cargo/bin/cargo +1.95.0 check --offline --locked --workspace --all-features --lib --manifest-path trillionnium/Cargo.toml -j2
/home/qian-qi/.cargo/bin/cargo +1.95.0 clippy --offline --locked --workspace --all-features --lib --manifest-path trillionnium/Cargo.toml -j2 -- -D warnings
```

两条返回 0，复用缓存后的 runner 计时各约 1.00 秒；这是工程观测，不是产品性能验收。M6 `cargo fmt --all --check` 在 source preparation 中实际通过。

## 证据包与仍开放的门槛

- `validation-logs-01.tar.gz`：180 个原文件及 manifest。包含 full commands/stdout/stderr/source/provider/ELF身份/fingerprints、child原输出、交叉关联和完整测试状态。gzip mtime=0。node因 `--show-output` 保留了约7.44MB原stdout，未裁剪成功case输出。
- `controller-records-01.tar.gz`：9个原durable jobs的请求/start/status和18条完整stdout/stderr；一条中途只读尾日志SSH连接关闭的receipt亦保留，未因此重投job。
- `archive-summary.json` 为远端原字节；`remote-transfer-receipt.json` 绑定文件version及17个读取chunk；`local-validation.json` 记录180文件size/SHA与5/5实际identity join核验。
- `artifact-direct-crossjoin.json`、journal两份小原件和ignored作用域sidecar便于直接复核。`FILES.json` / `SHA256SUMS` 列出最终交付文件。
- 原M5主日志包 SHA `2ad7f1189e1286301beac719dc98bb92b1c73410cecb1d0da4ad096fdcec3e16` 已核实保持不变；更早 M4 失败包仍独立保存。

普通 daemon 的真实训练/评价/Selection或NoUpdate/安装/FinalUse/下一任务/冷恢复、原4秒Host、独立30秒campaign、History/capacity/churn分别服务验收、完整大模型冷下载/长期保管、独立运营/WAN/故障域/长期租约仍需各自真实证据。普通library测试、单机测试fixture与provider smoke不替代这些门槛。未运行额外压力campaign、外部攻击工作流、72h gate、examples或全workspace test。
