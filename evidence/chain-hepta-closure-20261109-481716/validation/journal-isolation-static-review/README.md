# Journal 冷重开测试隔离：独立静态审阅

**结论：所审 test-only diff 未见实质阻断，可冻结为新的测试源版本；M5 原始 EAGAIN 的持锁者和因果尚未定位。** 本次只读审阅，没有编辑仓库、编译、运行测试、重试或构建故障复现。

## 固定输入与原失败

原源为 M5 `3ad605ecdac4b3b123dff83c1cb7458430acd776`，tree `fbbb4dca143775bae75ea825ff502f368e122ebb`。canonical OpenSSL 3.5.9 node 原件记录完整顶层 roster 1398：**1358 passed / 1 failed / 39 ignored / 0 filtered**，退出 101。原测试 ELF SHA-256 为 `00d50474c4409a5b89d14e5a75abbc7ca83cd41f6bdf0ae8a9605e49cb10deaf`。

唯一失败在 `journal_tests.rs:230:63`：`drop(journal)` 后的 `Journal::open` 返回 IO `WouldBlock` / EAGAIN。保留的日志没有持锁 PID、锁 dev/inode 或该时刻 spawn/exec 时序，不能因此确认 fork 继承，也不能确认生产句柄泄漏。原失败及其 source/provider/ELF 身份继续保留。

七份 M5 源文件和十份原结果文件的完整 SHA-256、Git blob、字节数列在 [review.json](review.json)。当前被审测试文件为 blob `5882265bd8bfd7c982380270b0779803275e7be3`，SHA-256 `4aeac967ab618226d2ea5d20e8c7fd7d681dd00962573b2425cec712609e4215`；实际审阅差异存于 [reviewed.patch](reviewed.patch)。

## 源码证据与保留的契约

[Files](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/public_submit/pq/files.rs) 直接拥有 `lock: File`；取得锁时使用 CLOEXEC、NONBLOCK 和 `try_lock_exclusive`。[Journal](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/public_submit/pq/journal.rs) 直接拥有 Files。这两个模块未见句柄 clone、forget、into_raw 或自定义 Drop；本次核对它们的工作区字节与 M5 完全一致。发布注入点位于 rename 与目录同步之后；所选测试没有安装额外 callback，注入路径只返回错误。

[原用例](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/public_submit/pq/journal_tests.rs) 的 Fixture 创建唯一临时目录，使用原 60 秒 SubmitRecoveryPlan。原三项 sticky-error 断言、同进程 `drop`→`open`、冷重开后 `used_calls=1`、`attempts=1` 和 prepared 名称不存在均保留。

已审 patch 的父分支先 exec 当前同一 test ELF，然后子进程才创建整个 Fixture 和 Journal。child 仅执行原全限定测试名 `--exact`，单线程；父分支要求成功退出、`running 1 test` 及仅在原 body 全部完成后打印的唯一完成标记，保留 stdout/stderr。这样排除了过滤拼写错误运行零测试却被当作通过的普通收集失误。新增 live-owner 控制确认相同参数的第二次 open 返回 IO source 的 `WouldBlock`，不把任意错误当作互斥证据。

关键点是 **initialize、活 owner 拒绝控制、fault、drop、reopen 都在同一个 child 中**。如果该 child 仍保留原锁句柄，原 reopen 仍应失败；exec 不位于 drop 与 reopen 之间。将 producer 留在父进程、只把 reopen 移至 exec 后会让 CLOEXEC 绕过这项释放检查，不属于本次认可范围。

同一原 harness 中确有其他 current_exe 子进程测试，源码还含外部 mkfifo Command；这些只能说明并行 subprocess 活动可能存在，不能建立本次失败的时间重叠或锁归属。现成 [migration 子进程模式](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/store/authenticated_migration_tests.rs) 与 [完成标记模式](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/3ad605ecdac4b3b123dff83c1cb7458430acd776/trillionnium/crates/trnm-pon-node/src/operator_task_policy_file_tests.rs) 提供仓库内语义先例；本 patch 没有引入后者的 sleep/poll 行为。

## 限定范围

本次修改只隔离测试调度，没有放宽生产非阻塞互斥、预算、验签、重放、失败状态或原断言，没有新增 ignored 用例，也没有 retry/sleep/unlock。没有为 child 添加独立 deadline；已有全库 runner 的工程 timeout 仍负责停止或判定停滞，不能将原 60 秒 plan 解释为新工程执行上限。任何超时必须保持失败或未完成。

静态认可这项隔离不要求先完成原 EAGAIN 因果调查；但将来若要宣称因果已关闭、修改生产锁或证明生产多进程 spawn 交互安全，需要同一次失败的锁对象身份、FD/owner 与进程时序证据。若隔离用例仍失败，应保留失败并诊断，不绕过互斥或重试至通过。

本审阅没有观察新 patch 的 native 终态，不能据此将旧 M5 失败改为通过，也不授予普通 daemon、原 Host 4 秒、独立 30 秒 campaign 或独立故障域 72 小时资格。新提交和新 ELF 的结果须另行绑定。
