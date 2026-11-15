# M15 发布、安装和消费入口读回

冻结来源：`e36cfb88956a0e35e53d74c5ab71c94c628439d9`，tree `b2586f06e82de55484a2e5752563e8b669c3ea17`。这是只读源码清点，未运行产品入口或测试，未修改仓库和已冻结 reader。JSON 伴随文件记录 10 组入口、35 个实际源码文件的 SHA-256、符号位置和受限范围内的生产引用扫描。

## 建议更新审计表的“发布与治理”行

| 当前情况 | 审计结论 |
| --- | --- |
| 真实 ML-DSA 角色/轮换已接显式 Linux M15 持久 owner、签名前沿服务、实际封存 ELF 安装/启动、一次性 Claim，以及 Node 打开和控制帧的当前授权复核；四类发布记录均可持久化。 | 已形成具体 Node 安装—启动—消费接线。完整安装/升级入口、Cell CURRENT/运行时激活、FinalUse/外部效果组合，以及独立密钥托管和新鲜恢复锚点仍未验收；不能据此宣称完整治理或整链 PQ。 |

这里的“已接线”指当前源码中的真实普通 CLI 和实现，不代表本次已经执行过其独立普通二进制闭环。`HOLD` 及所有生产、整链 PQ、独立托管/恢复资格保持 false。

## 真实入口和授权消费点

下表 `N/` 为 `trillionnium/crates/trnm-pon-node/src/`，`R/` 为其中的 `release_owner/`。

| 普通入口 | 实际接线与持久化 | 关键源码/函数 |
| --- | --- | --- |
| `m15-release-owner-initialize-v1`、`m15-release-owner-status-v1` | 固定 OS 部署根决定 namespace、owner 目录和受保护 trust 配置。创建要求外部新鲜 absence；打开/状态重放真实 proof history 并比对独立 frontier。结果不授执行。 | `N/main.rs::run`；`N/release_owner.rs::run_admin`；`R/owner.rs::Owner::{initialize,open,reload}` |
| `m15-release-owner-publish-v1 --publication` | 接收 canonical RootRotation / Release。1–4 分别为 NodeSoftware、ProtocolConfiguration、CellManifest、CellActivation；发布记录、安装记录、启动尝试和 Claim 都进入完整 index。时间由 owner 获取，候选输入不能指定观察时间。 | `R/proof_wire.rs::Publication/role`；`R/proof_state.rs::State::verify_publication_material`；`R/owner.rs::Owner::publish` |
| `m15-release-owner-install-v1 --artifact --artifact-name` | 检查当前软件角色和真实 bundle 中的名称/hash/size/platform；复制并封存真实 ELF，持久存入 `artifact-<digest>.elf`，提交 Installation。 | `R/catalog.rs::install`；`R/sealed.rs::Sealed`；`R/elf.rs::verify`；`R/files.rs::put_sealed` |
| `m15-release-owner-launch-v1` | 调用者不能另选 root、路径、argv 或 environment。签名配置决定完整 contract；持久 LaunchAttempt 后再次获取当前授权，对同一个 sealed FD 调用 `execveat`。 | `R/launch.rs::execute`；`R/execution_wire.rs::Contract::validate`；`R/owner.rs::{revalidate_current,finish_observation}` |
| `operator-continuous-m15-v1` | 在真实 Node 打开前提交一次性 Claim，绑定实际映像、进程身份、参数、环境、配置 FD 和工作目录。后续每个控制帧在实际 Node mutex 已取得后重新接入当前授权；Refresh 还要匹配新签名 policy 的 inputs digest。 | `N/main.rs::m15_continuous_command`；`R/consumer.rs::{Session::consume,Session::admit,Admission::revalidate}`；`N/operator_continuous_controller.rs::{open_configuration,apply}` |
| `m15-release-owner-frontier-initialize-v1`、`m15-release-owner-frontier-serve-v1` | 独立非 root UID/key/storage 的签名前沿服务；真实 expected→next CAS、随机 challenge/request/domain 绑定、可信时间窗口、锁与 fsync 后回复。重开要求独立保存的完整 `expected_frontier` 和 `expected_time_floor`。 | `R/frontier_service.rs::Service::{open,answer,serve}`；`R/service_store.rs::Store::{open,decide}`；`R/service_configuration.rs::Configuration` |

持久性不是只保存一个“已验证”布尔值。`R/transaction.rs::commit_with_files` 的顺序为：重查本地/外部 current → 完整候选验证 → fsync `pending.json` 和 `attempt.json` → 再验证 → 独立 CAS → 读回确切胜出 frontier → 完成 index 清理。`open_existing` 只完成外部已提交的完全相同候选，无法判断的状态保持 fenced，不重新 CAS 或启动。

`R/files.rs` 持有独占锁，反复检查目录/锁身份，使用 immutable 对象及原子 rename、文件与目录 fsync、完整读回。`R/owner.rs::reload` 每个新操作重放记录并做实际签名/角色检查；历史上未过期的事实不会被当作当前许可。

## Cell、治理和全系统边界

**Cell 角色记录确实能够沿 M15 持久化，但运行时激活没有因此接通。** `trnm-release-bundle/src/pq_release.rs::accept_with_quorum/check_current` 要求 CellActivation 指向同内容、未过期、当前 root generation 的 CellManifest；版本继续增加，历史内容回选需显式批准。M15 的 `State::verify_publication_material` 保留这些角色事件。

实际 Node 启动使用的 `R/proof_state.rs::current_contract` 只消费 NodeSoftware 和 ProtocolConfiguration。受限生产源码引用扫描没有发现消费 CellActivation 的 Cell CURRENT/模型执行入口；这不是对其他仓库或动态代码的完备性证明。

`trillionnium/crates/trnm-data-availability/src/bin/trnm-cell.rs::ReleaseAuthentication::verify` 是另一条实际获取路径：从 CLI 获得 network、parameters、key pin、generation、sequence 和时间，执行 PQ release 校验，并收紧原始获取 deadline。`cell/pq.rs::VerifiedCellPqReleaseV2::release_at` 已要求完整 current expectation，拒绝仅给时间的旧 API。但该 CLI 固定的是一次获取的 policy，没有连接 M15 当前 frontier；它不更新 CURRENT、不授 FinalUse、不证明模型质量，也不撤销已经进入的外部效果。

`trnm-governance-guard/src/lib.rs::GovernanceGuard` 仍是局部 caller-role、timelock、version 组件。M15 的已签 Node 配置并不能证明这套局部 guard 已成为完整 PQ 网络治理入口。

必须继续保留以下开放项：

- **独立 custody 与恢复锚点。** 固定 `/etc/trillionnium/m15-operator-deployment-v1.json`、独立签名 clock/frontier、offline quorum、私钥种子和预停机完整 frontier/time-floor pins 均需要实际部署与独立保存证据。本次未检查生产秘密或恢复设备。
- **实际 effect 语义。** LaunchAttempt/Claim 是已消耗的预约，不是 exec、Node open 或外部业务效果已经完成的证明。源码明确 CAS 与进入 kernel 不原子；unknown 留存，不产生新 dispatch。
- **不同 rollback 域。** M15 frontier 提交本 owner 的完整 index；PNQ2 `PqWitnessV4` 的三张网络表、M03 完整 checkpoint journal、全账本、Cell 和 FinalUse/ProviderEffect 不是同一个保护范围。全域同时回滚仍需独立新鲜事实。
- **入口组合。** M15 是显式 Linux x86_64/aarch64 static ELF profile，拒绝 PT_INTERP/外部动态依赖；普通 `operator-continuous`、开发 CLI、`trnm-cell`、LLM 安装/材料工具和完整 TUF updater 不会自动加入该 profile。M15 `receiver_service` 背景入口还明确返回 `M15_BACKGROUND_RECEIVER_UNSUPPORTED`。
- **独立验收。** 真实签名/持久文件/进程隔离测试不是跨主机运营、物理掉电、签名设备、持续服务或全系统 PQ 验收。

## 本轮执行证据不能混用

冻结 e36 的 full Node 命令仍在运行时，原始未完成日志已出现 **8 条 `release_owner::service_tests::*` 的 FAILED 行**，涉及真实签名 CAS、时钟/准备后到期、丢回复后的冷恢复、准备失败、错误签名/域/nonce、反向时间 floor 和最后回调漂移等。此时全日志共观察到 31 条 FAILED 行，完整父级汇总和 panic 细节仍未完成；这些数字是部分日志观察，不是最终计数。源码入口存在不能变成当前 M15 service 已通过资格，必须保留失败，并等待真实完整 readback。JSON 保存了此次部分日志前缀的字节数/hash及准确 8 个名字，未推断原因。

普通 M15 启动闭环的准确 selector 是：

`release_owner::native_consumer_tests::isolated_fixed_root_static_node_claim_refresh_and_revocation`

该测试有显式 `#[ignore]`，要求已审阅 static Node/test ELF 和全新 rootless user/mount/PID namespace；其原始界限为 32 steps / 180 seconds / RPC 2 seconds，fixture principals 为 UID 1000 和 1001。`scripts/m15_static_native_build.py` 与 `scripts/m15_isolated_native_run.py` 为其独立入口。当前 13 条 native plan 没有选择这一 ignored case，full Node library 不能冒充该 ordinary binary 的执行结果。

已有 `evidence/pq-m15-native-followthrough-20261107/README.md` 绑定历史 `1c14fab4` 的 1,249 passed / 33 ignored library suite，文档也明确 library ELF 并非普通 CLI。本清点没有发现并验证新的 e36 隔离消费者 raw 运行记录，因此不为其写“已执行通过”。

旧 `docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md` 中“没有 M15 installer/configuration consumer”的句子已被上述实际接线超越；其 Cell runtime/FinalUse、独立托管和完整验收的开放项仍应保留。本轮冻结期间未修改该文档。
