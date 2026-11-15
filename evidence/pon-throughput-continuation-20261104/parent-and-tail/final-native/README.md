# Final local native verification — separate b811 and 69d2 identities

最终合成源码的本地实际结果为 **253 个不同原生测试通过：Node 127、M06 113、SQLite 13**；另有三个 crate 的严格 Clippy 通过。**这不是完整 Node 套件通过**，不包含 hosted 业务 campaign、四秒确认、WAN/PQ 网络、发布或激活资格。

机器可读入口：[summary.json](summary.json)。精确的 crate/selector 去重清单：[final-passed-selectors.json](final-passed-selectors.json)。本包仅复制已完成的原始观测和验证其一致性，没有新建原生运行、重跑样本或修改生产源码。

## 源码与 ELF 身份分开记录

| 观测 | 实际源码基底 | 1,190 输入 map SHA256 | Node ELF SHA256 |
|---|---|---|---|
| 先前 b811 合成版本 | `b8116f65789a85148254f870c678a44f895316de` + 当时协作改动 | `27920633e57be739926218c370ecfbdfea624df71d84b89c2f9e3fc6f48605d2` | `7cef941c2174339125cbc43d56ed6b79976466ec225388860e1b20415ff889c3` |
| 最终 69d2 合成版本 | `69d2e06c48bbbd1e22432f9b557727b140aba361` + 最后五个 native 路径改动 | `ccc0b180a702aa012bb24ca0541c9d91592239083c141e3a289f0345acf9df8c` | `5349b31b55279a52dd75b679c5c3a12cb0c0d784dc259098409bb376f056045d` |

两组都是 **dirty composed source**，不是裸基底提交的运行结果。各项 before/after 源清单相等；执行 Node 的记录也核对了该项 ELF 前后哈希。完整观测映射见 [source-observations.json](source-observations.json)，追加九项还有每项独立守卫收据。

两个 native map 的唯一字节差异是 `trillionnium/crates/trnm-pon-node/tests/ancestry_long_sync.rs`，见 [manifest-difference.json](source/manifest-difference.json)。即使只改一项，也保留两组构建和测试结果，不把 b811 的通过移贴到新源码。这里的 `--lib` 构建和运行本身没有执行该独立集成测试。

Node ELF 的记录大小分别为 395,050,296 与 395,055,640 字节；本包保存身份和构建记录，不复制二进制。输入 map 覆盖当前 workspace 文件与保留的外部 literal src/build includes，不声称整个仓库、文档、workflow 或提交 metadata 在运行期间不变。

## 实际运行计数

b811 与 69d2 各自完成下列核心 Node 选择，共 **118 个不同 selector 通过**。二者的日志分别保留，不合并计数为一个版本的通过数。

| 核心 Node 分组 | passed | failed | 本次选择中的 ignored | 最终原始 stdout |
|---|---:|---:|---:|---|
| DirectAppend + 既有 reorg readback | 8 | 0 | 0 | [append-reorg](69d2/native/append-reorg.stdout) |
| native authenticated 模块 | 90 | 0 | 1 | [authenticated](69d2/native/authenticated.stdout) |
| archive native store 模块 | 14 | 0 | 4 | [archive-store](69d2/native/archive-store.stdout) |
| 六个精确 TCP/取消控制 | 6 | 0 | 0 | [完整逐命令收据](69d2/native/result.json) |
| **核心合计** | **118** | **0** | **5** | [对应选择清单](summary.json) |

随后使用相同最终 ELF 完成了 [九项此前未覆盖的 workspace 控制](69d2/workspace-nine/result.json)：root digest 三项、Growth 两项、当前 SQL 一项、History 三项。九项各有原始 stdout/stderr、精确 reader 输出和执行前后 source/ELF/reader/wrapper 守卫，均通过。与核心 118 项的交集为空，故最终 Node 实际通过 **127 个不同 selector**。选择依据及核心日志绑定见 [selection.json](69d2/workspace-nine/selection.json)。六项加九项的十五次 reader 通过不计作额外原生测试。

最终 Node 的 [全部注册清单](69d2/native/registry-all.stdout.gz) 是 **1,019 项**，其中 [27 项 ignored](69d2/native/registry-ignored.stdout)。注册清单只是 ELF 中的测试名称；它不表示 1,019 或 992 个非 ignored 测试全部执行。上述 Node 模块运行中的 5 项 ignored 也没有执行性能测试体。

| 最终组件 | 实际结果 | 完整性范围 | 原始 stdout |
|---|---|---|---|
| M06 / `trnm-mvcc-fee` | **113 passed / 0 failed / 7 ignored / 0 filtered** | 完整普通 libtest；注册 120 项，7 项 ignored 未执行 | [m06-complete-library](69d2/components/m06-complete-library.stdout) |
| 原 SQLite transaction scope | **13 passed / 0 failed / 0 ignored / 0 filtered** | 原有十三项；没有启用已归档 known-write 九项候选 | [sqlite-original-transaction-scopes](69d2/components/sqlite-original-transaction-scopes.stdout) |
| 严格 Clippy | exit **0** | Node、M06、SQLite 三个 crate，`--lib --tests --all-features -- -D warnings` | [command](69d2/clippy/clippy.json)、[stderr](69d2/clippy/clippy.stderr) |

253 是三个 crate 实际执行的不同测试身份数量，不是吞吐量或覆盖率百分比。报告中的 wall/CPU 数字保留了实际运行上下文，不用于比较版本性能或推导 TPS。parent-carry 与未过门槛的 M06 successor 保持独立归档、默认未启用；本包不继承它们的旧 native 资格。

## 实际 Cargo 特性与 profile

所有构建使用记录的原仓库 test profile，未改 profile 换取通过。以下直接来自 Cargo compiler-artifact，而不是根据二进制目录名推断：

| Test executable | features | opt_level | debug_assertions | overflow_checks |
|---|---|---:|---|---|
| Node | `default`, `pq-native-openssl` | `3` | true | true |
| M06 | `default`, `pq-native-openssl` | `1` | true | true |
| SQLite boundary | 空集合 | `0` | true | true |

各项 `test=true`、`debuginfo=2`。Node 的实际 [compiler-artifact](69d2/build/compiler-artifact.json) 与组件完整 [构建及运行收据](69d2/components/result.json) 保留 executable、features、profile 等字段。M06 ELF 为 `4e411e4057438162f4cc333c384f23931399e0493e86c3d4ed90d1cc6207c43a`；SQLite ELF 为 `09b4ae6b01be2f910932542cbd1689fe81f8881353a4d0e9ebd8cbc32b312798`，组件执行前后分别相同。

## 原始记录入口

| 版本 / 阶段 | 原始终态收据 | 构建或检查 stdout | stderr |
|---|---|---|---|
| b811 build | [result](b811/build/result.json) | [Cargo JSON gzip](b811/build/build.stdout.gz) | [stderr](b811/build/build.stderr) |
| b811 native | [result](b811/native/result.json) | 各 selector 原日志均在同目录 | 各 selector 原 stderr 均保留 |
| b811 Clippy | [result](b811/clippy/result.json) | [stdout](b811/clippy/clippy.stdout) | [stderr](b811/clippy/clippy.stderr) |
| 69d2 build | [result](69d2/build/result.json) | [Cargo JSON gzip](69d2/build/build.stdout.gz) | [stderr](69d2/build/build.stderr) |
| 69d2 native | [result](69d2/native/result.json) | 各 selector 原日志均在同目录 | 各 selector 原 stderr 均保留 |
| 69d2 Clippy | [result](69d2/clippy/result.json) | [stdout](69d2/clippy/clippy.stdout) | [stderr](69d2/clippy/clippy.stderr) |
| 69d2 components | [result](69d2/components/result.json) | [Cargo JSON gzip](69d2/components/build-components.stdout.gz) | [stderr](69d2/components/build-components.stderr) |
| 69d2 extra nine | [result](69d2/workspace-nine/result.json) | 每项 test-N.stdout | 每项 test-N.stderr |

每条命令收据保存实际 argv、cwd、起止时间、exit 和原 stdout/stderr SHA。空日志也保留。复制时只在完整 result.json 已完成且与 before/after 收据一致后收录；没有把半写 JSON 或仍运行的进程计为通过。

## 五路径 patch 与完整输入重建

[最终 native patch](source/native-from-69d2.patch.gz) 相对 `69d2e06c48bbbd1e22432f9b557727b140aba361`，只包含：

1. `examples/support/distributed_source_inventory.rs`；
2. `src/error.rs`；
3. `src/ingress/public_v3.rs`；
4. `src/store.rs`；
5. 新增 `src/store/append_readback_tests.rs`。

五项均位于 `trillionnium/crates/trnm-pon-node/`。patch 的目标字节从已暂存源码读取，并逐项匹配最终 native manifest；它不包含其他候选源码、文档或 workflow。整理时在一次性 scratch 树从完整基底恢复输入，再应用 patch，核对了 **全部 1,190 项输入**；同一 patch 在独立 b811 基底上也精确恢复其历史 27920633 map。完整结果及每个 patch 路径 SHA 见 [patch-verification.json](source/patch-verification.json)。

未来人工复现时，在独立干净 checkout 选择相应完整 base 后应用 patch，不在正常工作树叠加。令 `final_native_evidence` 指向本包的绝对路径，以下示例恢复最终 69d2 的输入：

```bash
gzip -dc "$final_native_evidence/source/native-from-69d2.patch.gz" | git apply -
python3 - "$final_native_evidence/69d2/build/source-before.json.gz" <<'PY_VERIFY'
import gzip, hashlib, json, pathlib, sys
manifest=json.loads(gzip.decompress(pathlib.Path(sys.argv[1]).read_bytes()))
for name, expected in manifest["native_input_files"].items():
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==expected, name
canonical=json.dumps(manifest["native_input_files"],sort_keys=True,separators=(",",":")).encode()
assert hashlib.sha256(canonical).hexdigest()==manifest["manifest_sha256"]
print(manifest["manifest_sha256"])
PY_VERIFY
bash scripts/project-preflight.sh
```

构建需使用相同 Rust 1.95.0 和仓库既有 [PQ provider 准备脚本](../../../../scripts/ci/prepare_pq_provider.sh)。原命令是 `cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features --no-run --message-format=json`；组件命令以相同选项选择 `trnm-mvcc-fee` 和 `trnm-sqlite-io-boundary`。环境路径应按独立环境调整，保留正常 rustup shim、原 features/profile 和所有资格检查。重建位置或工具链依赖改变可能改变 ELF 字节，应记录实际新哈希。

构建取得实际 test ELF 后，按归档 argv 的 selector、`--exact`（精确项）、`--show-output` 和 `--test-threads=1` 执行；不要扩大原通过声明。原始命令中的绝对路径是 provenance。[run-final-native helper 快照](provenance/run-final-native.py.txt) 与 [wrapper 快照](provenance/run-throughput.sh.txt) 只用于理解命令，不是仓库生产实现；helper 在系列运行中增加过 components 支持，因此本包不声称每个历史 action 使用了当前快照的逐字节版本。实际命令和原生源码/ELF 收据才是历史身份依据。追加九项还独立固定了 wrapper 和 [required-test reader](provenance/check_required_native_test.py.txt) 的实际哈希。

以上是未来复现说明；本次包装没有执行构建或 native 测试。此包也不替代最终提交的源完整性检查、完整 original-workspace CI 或业务门槛。

## 完整性

在本目录运行 `sha256sum --check SHA256SUMS`。可压缩的大日志使用 gzip，mtime 固定为零；[copy-verification.json](copy-verification.json) 同时保存原始字节 SHA 与存储 payload SHA，解压后与原始日志逐字节一致。[validation.json](validation.json) 记录包装时的计数、链接和复制校验。
