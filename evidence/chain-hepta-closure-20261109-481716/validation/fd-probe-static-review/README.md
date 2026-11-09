# FD 身份探针：独立静态审阅

日期：2026-11-09。结果：**可冻结测试判据修正供实际复跑；无静态阻塞项。** 本记录没有运行编译或 native 测试，也不形成生产或安全资格。

M4 基线为 `e4e4a8e049915ba09d9e97444b4709ce8769ce81`。M5 在本次记录时尚未冻结，因此没有填入猜测的提交身份；后续证据 child 为 M6。

## 精确输入身份

| 输入 | 字节 | SHA-256 | 相对 M4 |
|---|---:|---|---|
| `sealed_loader/tests.rs` 当前 | 20679 | `4e100a4b194d253231d722491061dc869f0d64d00d1a990cc27c02492ec2b127` | 测试判据变化 |
| `sealed_loader/tests.rs` M4 | 19644 | `f9a696f9300cefe4e5b600fbda1a0e178da585774b2040608f0a35da09a949bd` | 原始失败版本 |
| 生产 `sealed_loader.rs` 当前及 M4 | 13057 | `5aa3eb47e0f1e380a89e785b6e4f42745a4f3e55d0f7618c52735d47d410889d` | **逐字相同** |

完整仓库路径、Git blob、父模块、三个 manifest 与 checker 的身份均在 [review.json](review.json)。本记录的生产 SHA 全长 64 位；以 JSON 和本表完整值为准。

## 静态判断

`observe_fd` 在原 `&File` 存活时记录 `fd/dev/ino`。probe 继续拒绝同一槽位指向原设备／inode，只接受 NotFound 或不同身份；其他 I/O 错误继续失败。观察结构不复制 fd 所有权。

新增 `closure_probe_rejects_a_live_original_descriptor` 使用指定消息的 `#[should_panic]`，保持原 tempfile 在检查期间存活。创建文件、metadata 或 `/proc` 访问的其他 panic 不满足该指定消息，不能冒充负控通过。Linux 父模块 cfg 与 `MetadataExt` 导入一致；既有 `super::*` 继续提供 `File/io`。

生产路径先由局部 `File` 拥有新 memfd，验证后移入 `Vec<SealedMember>`，全部成员完成后才返回 bundle。所读错误返回会释放当前 File 及已收集成员；生产字节未变。三个原测试的错误类型、完整哈希、usage、selection 和观测数量断言均保留。

该判断只覆盖原 fd 槽位与 `(dev, ino)` 身份；它不证明全部 dup／mmap 下游引用回收，也不证明唯一 open-file-description。旧失败不能被写成已证明生产泄漏或已确定发生了复用。

## 源绑定成员检查

| 固定清单 | 确切字段 | 路径数 | 修改文件是否在内 | 此测试变更是否要求重绑 |
|---|---|---:|---|---|
| `config/pon/pq-authority-effects-v1.json` | `source_files_sha256` | 44 | 否 | 否 |
| `config/pon/pq-root-dependency-register-v3.json` | `source_files_sha256` | 37 | 否 | 否 |
| `config/pon/w1-qrom-implementation-current-v2.json` | `local_path_closure.files[*].path` | 137 | 否 | 否 |

W1 的 16 个 `project_files` 也不包含该文件，其 6 个 `crate_roots` 不含 `trnm-data-availability`。三份 manifest 与相应 checker 都仍等于 M4 字节。不得把这一有限清单结果扩张为整个程序没有相关依赖。

确切需要 root 更新的位置是 `config/pon/pq-cross-branch-corpus-v1.json` 的 `pinned_blobs["trillionnium/crates/trnm-data-availability/src/cell/residency/sealed_loader/tests.rs"]`：本次观察值 `a3d07422e7894ee0203f050ca6d09b602e1d6d5e`，应绑定当前 reviewed blob `a3d07422e7894ee0203f050ca6d09b602e1d6d5e`。`required_paths` 已包含该路径，无须新添。本人没有修改该 corpus 或任何 repo 文件。

authority／Root／W1 的固定 revision 常量和 selected proof descriptor 不因这一测试文件变更而需要改写；这些登记仍是各自有明确范围的既有源映射。M5 实际复跑必须绑定新的源码、二进制与输入，不能把 M4 失败结果移名为 M5 成功。
