# M4 原生验证交付

## 结论

固定候选 M4 的 workspace / all-features / library 范围 cargo check 和 Clippy 均通过。五个 owner crate 的既有库测试门槛未关闭：冷构建尝试 02 在工程时限到达时停止；保留全部原件、核对原进程已停止后，唯一获授权的暖缓存尝试 03 出现真实断言失败。未再发起测试重跑。

此包属于编译、静态检查与既有库测试证据。普通 daemon 的学习闭环、原 4 秒 Host 服务、独立 30 秒 campaign、独立故障域、持续租约、WAN 和长期运行验收都没有由此次操作完成。原服务阈值、源码与断言未修改。库测试中已存在的本机 TCP 或证明测试夹具保持其原有范围。

## 固定身份与范围

- Chain HEAD: e4e4a8e049915ba09d9e97444b4709ce8769ce81
- Tree: c82829c3a5710960081d91930cf425f9a768e9e4
- Cargo.lock SHA256: f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd
- Source bundle: 98,652 bytes; SHA256 cb6d7b9e77e2eeb259adc013cd09a7d8097c2734550f66c398fcf5b972f599f3
- Host: 已配置的 ROG；原 Mac HeptaRuntime 控制器；工具链 1.95.0；Cargo -j2。
- 隔离目录: /home/qian-qi/chain-hepta-481716-native-check
- check/Clippy target: 同目录下 target。
- 库测试 target: 同目录下 retained-test-target-01。
- 所有实际 Cargo 检查与测试维持 --offline --locked；未放宽离线要求或拉取新的依赖。
- Source checkout 仅 sparse 排除顶层 evidence；native/config/formal 文件保留。各阶段及最终收集的 HEAD、tree、锁文件摘要与 clean 状态一致。

环境最初在共享本地磁盘写日志时失败，Cargo 尚未启动；local-not-started 记录在控制器包中保留。之后在明确授权的隔离 ROG 目录执行。ROG 初始探测为 32 个逻辑 CPU，根文件系统空闲 91,075,686,400 bytes；资源原记录可查。

## 实际结果

| 阶段 | 实际结果 | 证据边界 |
| --- | --- | --- |
| workspace all-features library check | rc 0，39.009401555 秒 | 编译检查通过 |
| 同 scope Clippy，-D warnings | rc 0，30.007221033 秒 | 静态门槛通过 |
| retained tests 01 | NOT_STARTED | 请求中的 trnm-release-runtime 不存在；metadata 拒绝，未运行测试 |
| retained tests 02 | inner timed_out=true，Cargo -15；外层 exit 2 且 timed_out=false | 约 850 秒工程窗口，含 7 分 45 秒冷编译；库测试未完整结束 |
| retained tests 03 | Cargo 101；23.932759582 秒；timed_out=false | 暖缓存重跑出现真实库断言失败，五库范围未完成 |

尝试 02 仅出现三个 Cargo Running unittests 头：trnm-crypto-primitives、trnm-data-availability、trnm-pon-node。前两个完整顶层总结分别为 196 与 714 passed，均 0 failed/ignored/filtered。node 在工程终止时未完成；protocol 与 release-bundle 未执行。

尝试 03 仅出现两个实际 Cargo 库头：crypto 的 196 项全部通过；data-availability 为 713 passed、1 failed、0 ignored、0 measured、0 filtered。Cargo 随失败停止，node、protocol、release-bundle 未执行。不同尝试的结果不相加。

失败测试：

cell::residency::sealed_loader::tests::copied_byte_corruption_is_rejected_by_postseal_full_hash_without_partial_bundle

原位置：trillionnium/crates/trnm-data-availability/src/cell/residency/sealed_loader/tests.rs:465。断言读取 /proc/self/fd/{fd} 应得到 NotFound 失败。该输出只能证明此断言在本次运行失败；文件描述符复用、测试并发或生产实现问题仍须另行审阅。未将其直接推断为生产泄漏。

## 02 原汇总错误及更正

retained-tests/test-02/summary.json 保留原始内容。其旧 runner 把 node 的三个嵌套子进程总结（每个 1 passed、1397 filtered）误当另外三个 owner 库，写出错误的 all_five_library_targets_reported、library_targets_reported、aggregate_counts。

这些三个字段不能用于判断五库完成，也不能把嵌套总结与顶层结果相加。stop-review-02/count-correction.json 提供明确更正：仅两个完整顶层库总结，共 910 passed；node 未完整总结；另两库未运行。旧原件未覆盖。尝试 03 的映射以实际唯一 Cargo 库头与无过滤顶层总结对齐，嵌套结果独立保留。

stop-review-02/summary.json 保留暖重跑前 systemd 原 unit、cgroup 与自有 cwd/executable 进程检查：原执行已停止，未发现残留自有执行，没有断言或编译失败。只有这一明确条件下发起了获授权的第 03 次尝试。

## 原命令

check / Clippy 使用：

    /home/qian-qi/.cargo/bin/cargo +1.95.0 check --offline --locked --workspace --all-features --lib -j2 --manifest-path trillionnium/Cargo.toml
    /home/qian-qi/.cargo/bin/cargo +1.95.0 clippy --offline --locked --workspace --all-features --lib -j2 --manifest-path trillionnium/Cargo.toml -- -D warnings

尝试 02 与 03 的实际测试 argv 完全相同：

    /home/qian-qi/.cargo/bin/cargo +1.95.0 test --offline --locked --all-features --lib -j2 -p trnm-crypto-primitives -p trnm-release-bundle -p trnm-protocol -p trnm-pon-node -p trnm-data-availability --manifest-path trillionnium/Cargo.toml

原命令、cwd、环境覆盖、开始时刻、资源状态、退出与输出摘要位于各阶段 commands.json。外层 Hepta 时限 900 秒；内部工程总窗口约 850 秒。该工程窗口与原 Host/campaign 服务时限无替代关系。

metadata 中 selected_targets 保存每个 package 的全部目标声明，其中可包含 example/integration 声明；它不是执行证据。实际 argv 指定 --lib，实际执行由 Cargo stderr 的 Running unittests 记录确定。

## 实际测试 ELF

只从 Cargo stderr 实际报告的文件读取身份，没有用 glob 推断执行：

| crate | 出现的尝试 | bytes | SHA256 |
| --- | --- | ---: | --- |
| trnm-crypto-primitives | 02、03 | 59,820,968 | ca0f7f7c7a8a0d2bee57333237bb84af69676e957f6f40ff00004d07da1b69c3 |
| trnm-data-availability | 02、03 | 128,517,000 | 62d97d12f375842d92372542810ae95bfaf5fda6af1109b53680d09a2221607a |
| trnm-pon-node | 02 | 569,279,696 | 2b9601812d1a5f23b897218d03a95fcb221a146aaad088877310435dc56321d1 |

这些都是 cfg(test) / test profile ELF。普通 daemon 的 build/load 身份字段为 null。02 在重跑前采集的 crypto/DA 身份与 03 后相同；node 仅说明 02 曾开始运行，不能表示其完成。未把 ELF 或 build target 复制进证据包。

## 文件与原任务

validation-logs-01.tar.gz 是 ROG 直接生成并回收的确定性 gzip/tar，159,519 bytes，SHA256 856524b9bb284a83fe12ed098da9858a687d08e25ddad0ed5c7121f1e38f15c6。它包含 93 个原文件与 evidence-manifest.json，共 94 个成员。回收固定同一远端 version，逐块 SHA256、整包 SHA256、每个 manifest 成员的大小与 SHA256 全部核验通过。manifest SHA256 为 05eb5a3dc8627346541ca8ce00dd10f195a5c93ffd17233bf13a975ed8ef09fd。

controller-records-01.tar.gz 保存完整命令请求、9 个 Hepta job 的终态回执、按原 byte cursor 取回的全部 18 路 stdout/stderr、传输校验、本地未启动记录与历史准备失败。每个流大小均与终态 stored 和 seen 一致。历史 collection-plan.json 是未执行的早期收集草案；实际执行请求为 collection-final-request.json。

| 阶段 | job ID | 稳定 key |
| --- | --- | --- |
| ROG probe | 1a1c0b4b6d0-11c5a-26 | chain-hepta-481716-native-host-probe-01 |
| 隔离目录 | 1a1c0ba20df-11c5a-3f | chain-hepta-481716-native-dir-01 |
| M4 source | 1a1c0c08bec-11c5a-56 | chain-hepta-481716-native-source-01 |
| check/Clippy | 1a1c0c2ef89-11c5a-5a | chain-hepta-481716-native-check-01 |
| tests 01 | 1a1c0cc9c04-11c5a-74 | native-retained-tests-01 |
| tests 02 | 1a1c0d2c5a4-336d-3 | native-retained-tests-02 |
| 02 停止核对/更正 | 1a1c0e69e1e-336d-27 | native-retained-tests-02-stop-review-01 |
| tests 03 | 1a1c0e8f2ea-336d-2b | native-retained-tests-03 |
| 原件收集 | 1a1c0ef211a-336d-39 | chain-hepta-481716-native-collect-01 |

建议纳入仓库时保留本目录全部小文件；无需复制原 build target 或既有 76 MB campaign ZIP。原服务 campaign 证据属于另一包，与此次原生验证独立。
